from hookline.parsing.auth_results import (
    MAX_RESULTS_PER_HEADER,
    parse_authentication_results,
    strip_comments,
)


def test_typical_header() -> None:
    parsed = parse_authentication_results(
        "mx1.larkspur.test;\r\n\tspf=fail smtp.mailfrom=mailer.example.test;\r\n"
        "\tdkim=none; dmarc=fail header.from=example.test",
        header_index=2,
    )
    assert parsed.unreadable == 0
    spf, dkim, dmarc = parsed.results
    assert (spf.method, spf.result, spf.properties) == (
        "spf",
        "fail",
        {"smtp.mailfrom": "mailer.example.test"},
    )
    assert (dkim.method, dkim.result) == ("dkim", "none")
    assert dmarc.properties == {"header.from": "example.test"}
    assert {r.authserv_id for r in parsed.results} == {"mx1.larkspur.test"}
    assert {r.header_index for r in parsed.results} == {2}


def test_comments_with_semicolons_and_quoted_values() -> None:
    parsed = parse_authentication_results(
        "MX.Example.Test 1; DKIM=Pass (2048-bit key; unprotected) header.d=Example.test "
        'reason="good signature; trusted"; dmarc=pass (p=reject sp=reject) action=none'
    )
    dkim, dmarc = parsed.results
    assert dkim.authserv_id == "mx.example.test"
    assert (dkim.method, dkim.result) == ("dkim", "pass")
    assert dkim.properties == {"header.d": "Example.test", "reason": "good signature; trusted"}
    assert dmarc.properties == {"action": "none"}


def test_method_version_is_accepted() -> None:
    (result,) = parse_authentication_results("mx.test; spf/1 = softfail").results
    assert (result.method, result.result) == ("spf", "softfail")


def test_no_result_header() -> None:
    parsed = parse_authentication_results("mx.test; none")
    assert parsed.results == ()
    assert parsed.unreadable == 0


def test_unreadable_entries_are_counted() -> None:
    parsed = parse_authentication_results("mx.test; this is not valid; spf=pass;;")
    assert [r.method for r in parsed.results] == ["spf"]
    assert parsed.unreadable == 1


def test_empty_header() -> None:
    parsed = parse_authentication_results("")
    assert parsed.results == ()


def test_header_without_authserv_id() -> None:
    (result,) = parse_authentication_results("; spf=pass").results
    assert result.authserv_id is None


def test_results_are_capped() -> None:
    value = "mx.test;" + "spf=pass;" * (MAX_RESULTS_PER_HEADER + 3)
    parsed = parse_authentication_results(value)
    assert len(parsed.results) == MAX_RESULTS_PER_HEADER
    assert parsed.unreadable == 3


def test_strip_comments() -> None:
    assert strip_comments("a (b (c) d) e") == "a   e"
    assert strip_comments('x="(not a comment)" y') == 'x="(not a comment)" y'
    assert strip_comments('x="say \\"hi\\"" (gone)') == 'x="say \\"hi\\""  '
    assert strip_comments("a \\( b (c \\) d) e") == "a \\( b   e"
    assert strip_comments("a ) b") == "a ) b"


def test_escaped_quotes_inside_quoted_values() -> None:
    (result,) = parse_authentication_results(
        'mx.test; dkim=fail reason="key \\"k1; old\\" revoked"'
    ).results
    assert result.properties == {"reason": 'key "k1; old" revoked'}
