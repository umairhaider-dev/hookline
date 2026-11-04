import pytest

from hookline.models import Link, LinkOrigin
from hookline.parsing import html as html_module
from hookline.parsing.html import MAX_LINK_TEXT, extract_html
from hookline.parsing.links import extract_text_links


def test_text_skips_scripts_and_styles_and_keeps_blocks_apart() -> None:
    content = extract_html(
        "<html><head><style>p {color: red}</style><title>T</title></head>"
        "<body><p>First   paragraph</p><div>Second<br>line</div>"
        "<script>var hidden = 1;</script><table><tr><td>a</td><td>b</td></tr></table>"
        "<!-- a comment --></body></html>"
    )
    assert content.text == "T\nFirst paragraph\n\nSecond\nline\n\na b"
    assert content.problems == ()


def test_entities_are_decoded() -> None:
    assert extract_html("<p>Fish &amp; chips &lt;3</p>").text == "Fish & chips <3"


def test_anchor_links_with_nested_markup() -> None:
    content = extract_html(
        '<a href=" https://portal.larkspur.test/\n\treset?a=1&amp;b=2 ">'
        "<b>Reset</b>   your <i>password</i></a>"
    )
    assert content.links == (
        Link(
            url="https://portal.larkspur.test/reset?a=1&b=2",
            text="Reset your password",
            origin=LinkOrigin.HTML_ANCHOR,
        ),
    )


def test_unclosed_and_nested_anchors() -> None:
    content = extract_html('<a href="https://a.test">one <a href="https://b.test">two')
    assert [(link.url, link.text) for link in content.links] == [
        ("https://a.test", "one"),
        ("https://b.test", "two"),
    ]


def test_forms_areas_and_image_alt_text() -> None:
    content = extract_html(
        '<form action="https://collect.example.test/post"><input name="pw"></form>'
        '<map><area href="https://area.test/x"></map>'
        '<a href="https://img.test"><img alt="https://larkspur.test" src="cid:logo"/></a>'
    )
    assert [(link.url, link.origin, link.text) for link in content.links] == [
        ("https://collect.example.test/post", LinkOrigin.HTML_FORM, ""),
        ("https://area.test/x", LinkOrigin.HTML_ANCHOR, ""),
        ("https://img.test", LinkOrigin.HTML_ANCHOR, "https://larkspur.test"),
    ]


def test_anchors_without_href_and_empty_attributes_are_ignored() -> None:
    content = extract_html('<a name="top">Top</a><a href="">Empty</a><form action></form>')
    assert content.links == ()
    assert content.text == "TopEmpty"


def test_self_closing_script_does_not_hide_text() -> None:
    assert extract_html('<script src="x.js"/><p>Visible</p>').text == "Visible"


def test_long_anchor_text_is_capped() -> None:
    content = extract_html(f'<a href="https://x.test">{"word " * 200}</a>')
    assert len(content.links[0].text) == MAX_LINK_TEXT


def test_tokenizer_failure_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(self: object, data: str) -> None:
        raise AssertionError("we should not get here!")

    monkeypatch.setattr(html_module._Extractor, "feed", explode)
    content = extract_html("<p>x</p>")
    assert content.problems == ("HTML body could not be fully parsed: we should not get here!",)


def test_text_links() -> None:
    links = extract_text_links(
        "Visit https://portal.larkspur.test/reset. Or www.larkspur.test/help, "
        "(see http://example.test/wiki/Thing_(disambiguation)) and https://portal.larkspur.test/reset!"
    )
    assert [link.url for link in links] == [
        "https://portal.larkspur.test/reset",
        "www.larkspur.test/help",
        "http://example.test/wiki/Thing_(disambiguation)",
    ]
    assert {link.origin for link in links} == {LinkOrigin.PLAIN_TEXT}


def test_text_links_inside_angle_brackets() -> None:
    (link,) = extract_text_links("Link: <https://larkspur.test/a?b=c>")
    assert link.url == "https://larkspur.test/a?b=c"


def test_blank_urls_are_dropped() -> None:
    assert extract_html('<a href="  ">x</a><form action="\t"></form>').links == ()


def test_unexpected_end_tag_while_skipping_is_ignored() -> None:
    extractor = html_module._Extractor()
    extractor.handle_starttag("script", [])
    extractor.handle_endtag("p")
    extractor.handle_data("still hidden")
    extractor.handle_endtag("script")
    extractor.handle_data("shown")
    assert extractor.text() == "shown"


def test_oversized_html_is_cut_and_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(html_module, "MAX_HTML_CHARS", 20)
    content = extract_html("<p>visible</p>" + "<p>hidden later</p>" * 3)
    assert "hidden later" not in content.text
    assert content.problems == ("HTML body has 71 characters; only the first 20 were analysed",)


def test_links_are_deduplicated_and_capped() -> None:
    anchors = '<a href="https://same.test">x</a>' * 5 + "".join(
        f'<a href="https://h{n}.test">x</a>' for n in range(5)
    )
    content = extract_html(anchors, max_links=3)
    assert [link.url for link in content.links] == [
        "https://same.test",
        "https://h0.test",
        "https://h1.test",
    ]
    assert content.links_dropped == 3


def test_text_links_stop_at_limit() -> None:
    links = extract_text_links(
        "https://a.test https://a.test https://b.test https://c.test", limit=2
    )
    assert [link.url for link in links] == ["https://a.test", "https://b.test"]
