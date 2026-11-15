"""Web upload page and JSON API.

Routes:

* ``GET /``: upload form.
* ``POST /analyze``: form upload, answered with the HTML report.
* ``POST /api/v1/analyze``: multipart upload (field ``file``), answered with the
  JSON report.
* ``GET /api/v1/health``: liveness and version.

Uploaded emails are never saved: each is discarded once the response is sent
(the multipart parser keeps uploads over 1 MB in a temporary file until then),
and request bodies are capped while they stream in. Every response carries a
strict Content-Security-Policy and ``Cache-Control: no-store``, because reports
contain email content. When ``HOOKLINE_WEB_TOKEN`` is set, uploads need it: as
a bearer token for the API, or in the form's token field.
"""

import logging
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import PurePath
from typing import Annotated

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from hookline import __version__
from hookline.config import Settings
from hookline.models.report import Report
from hookline.pipeline import Analyzer
from hookline.reporting import render_html
from hookline.reporting.escaping import escape_control_chars

logger = logging.getLogger(__name__)

API_PREFIX = "/api/v1"
READ_CHUNK_BYTES = 64 * 1024
# Room for multipart boundaries and form fields on top of the email itself.
MULTIPART_OVERHEAD_BYTES = 64 * 1024
MAX_FILENAME_CHARS = 200

PAGE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)
_SECURITY_HEADERS = {
    "Content-Security-Policy": PAGE_CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def create_app(settings: Settings, analyzer: Analyzer | None = None) -> FastAPI:
    """Build the web application around one shared analyzer."""
    owns_analyzer = analyzer is None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.analyzer = analyzer if analyzer is not None else Analyzer(settings)
        yield
        if owns_analyzer:
            app.state.analyzer.close()

    app = FastAPI(
        title="Hookline",
        version=__version__,
        description="Phishing email analysis: upload an .eml file, get the report.",
        lifespan=lifespan,
        # Swagger UI loads scripts from a CDN, which the CSP forbids; the
        # OpenAPI document itself is still served.
        docs_url=None,
        redoc_url=None,
        openapi_url=f"{API_PREFIX}/openapi.json",
    )
    token = settings.web_token.get_secret_value() if settings.web_token else None
    max_bytes = settings.max_email_bytes

    app.add_middleware(_BodyLimit, max_bytes=max_bytes)

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        length = request.headers.get("content-length", "")
        if length.isdigit() and int(length) > max_bytes + MULTIPART_OVERHEAD_BYTES:
            response: Response = JSONResponse(
                {"detail": f"upload is larger than the {max_bytes:,}-byte limit"},
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            )
        else:
            response = await call_next(request)
        response.headers.update(_SECURITY_HEADERS)
        return response

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def upload_page() -> HTMLResponse:
        return _page(needs_token=token is not None)

    @app.post("/analyze", response_class=HTMLResponse, include_in_schema=False)
    def analyze_form(
        request: Request,
        file: Annotated[UploadFile, File()],
        form_token: Annotated[str, Form(alias="token")] = "",
    ) -> HTMLResponse:
        if token is not None and not _same(form_token, token):
            return _page(token is not None, "The access token is missing or wrong.", 401)
        try:
            report = _analyze(request.app.state.analyzer, file, max_bytes)
        except _UploadError as exc:
            return _page(token is not None, str(exc), exc.status_code)
        return HTMLResponse(render_html(report))

    @app.post(
        f"{API_PREFIX}/analyze",
        summary="Analyze an email",
        responses={
            400: {"description": "Empty or unreadable upload"},
            401: {"description": "Missing or wrong bearer token"},
            413: {"description": "Upload larger than the size limit"},
        },
    )
    def analyze_api(
        request: Request,
        file: Annotated[UploadFile, File(description="The .eml file to analyze")],
        authorization: Annotated[str, Header()] = "",
    ) -> JSONResponse:
        """Analyze one uploaded .eml file and return the full JSON report."""
        if token is not None:
            scheme, _, provided = authorization.partition(" ")
            if scheme.lower() != "bearer" or not _same(provided, token):
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED,
                    "missing or wrong bearer token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        try:
            report = _analyze(request.app.state.analyzer, file, max_bytes)
        except _UploadError as exc:
            raise HTTPException(exc.status_code, str(exc)) from exc
        return JSONResponse(report.model_dump(mode="json"))

    @app.get(f"{API_PREFIX}/health", summary="Health check")
    def health() -> dict[str, str]:
        """Report that the service is up, and its version."""
        return {"status": "ok", "version": __version__}

    return app


class _BodyLimit:
    """Stops reading a request body once it grows past the upload limit.

    ``guard`` refuses requests whose Content-Length is too large, but a chunked
    upload declares no length, and the multipart parser would spool all of it
    to disk before the route could refuse it.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max_bytes + MULTIPART_OVERHEAD_BYTES:
                    raise HTTPException(
                        status.HTTP_413_CONTENT_TOO_LARGE,
                        f"upload is larger than the {self._max_bytes:,}-byte limit",
                    )
            return message

        await self._app(scope, limited_receive, send)


class _UploadError(Exception):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


def _analyze(analyzer: Analyzer, upload: UploadFile, max_bytes: int) -> Report:
    # Parsing never raises on malformed mail, so only the upload itself can fail.
    raw = _read_limited(upload, max_bytes)
    return analyzer.analyze_bytes(raw, source_file=_display_name(upload.filename))


def _read_limited(upload: UploadFile, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while chunk := upload.file.read(READ_CHUNK_BYTES):
        size += len(chunk)
        if size > max_bytes:
            raise _UploadError(
                f"upload is larger than the {max_bytes:,}-byte limit",
                status.HTTP_413_CONTENT_TOO_LARGE,
            )
        chunks.append(chunk)
    if not size:
        raise _UploadError("the uploaded file is empty", status.HTTP_400_BAD_REQUEST)
    return b"".join(chunks)


def _display_name(filename: str | None) -> str | None:
    """The upload's base name, cleaned for display. Paths from the client are dropped."""
    if not filename:
        return None
    name = PurePath(filename.replace("\\", "/")).name
    return escape_control_chars(name)[:MAX_FILENAME_CHARS] or None


def _same(provided: str, expected: str) -> bool:
    return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _page(needs_token: bool, error: str | None = None, status_code: int = 200) -> HTMLResponse:
    template = _templates().get_template("upload.html.j2")
    html = template.render(version=__version__, needs_token=needs_token, error=error)
    return HTMLResponse(html, status_code=status_code)


@lru_cache(maxsize=1)
def _templates() -> Environment:
    return Environment(
        loader=PackageLoader("hookline.web", "templates"),
        autoescape=select_autoescape(["html", "j2"], default=True),
    )
