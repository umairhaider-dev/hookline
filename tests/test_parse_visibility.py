import pytest

from hookline.parsing.html import extract_html
from hookline.parsing.visibility import ROOT, child_frame, normalize_colour, parse_style


def test_parse_style() -> None:
    assert parse_style("Display: NONE !important; color:#FFF;bogus;;font-size : 0px") == {
        "display": "none",
        "color": "#fff",
        "font-size": "0px",
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("white", "#ffffff"),
        (" #FFF ", "#ffffff"),
        ("#a1b2c3", "#a1b2c3"),
        ("rgb(255, 255, 255)", "#ffffff"),
        ("rgba(0,0,0,0)", "transparent"),
        ("rgba(10,20,30,0.5)", "#0a141e"),
        ("rgb(300,0,0)", "#ff0000"),
        ("transparent", "transparent"),
        ("#ff", None),
        ("hsl(0,0%,100%)", None),
        ("", None),
    ],
)
def test_normalize_colour(value: str, expected: str | None) -> None:
    assert normalize_colour(value) == expected


@pytest.mark.parametrize(
    ("attributes", "reason"),
    [
        ({"hidden": ""}, "hidden attribute"),
        ({"style": "display:none"}, "display:none"),
        ({"style": "visibility:collapse"}, "visibility:hidden"),
        ({"style": "mso-hide:all"}, "mso-hide:all"),
        ({"style": "opacity:0"}, "opacity:0"),
        ({"style": "opacity:0%"}, "opacity:0"),
        ({"style": "font-size:1px"}, "zero or one pixel font size"),
        ({"style": "max-height:0px;overflow:hidden"}, "zero size with overflow hidden"),
        ({"style": "color:#fff"}, "text the same colour as its background"),
        ({"color": "#000", "bgcolor": "black"}, "text the same colour as its background"),
        ({"style": "color:rgba(0,0,0,0)"}, "transparent text"),
    ],
)
def test_hidden_frames(attributes: dict[str, str], reason: str) -> None:
    assert child_frame("div", attributes, ROOT).hidden == reason


@pytest.mark.parametrize(
    "attributes",
    [
        {},
        {"style": "opacity:0.5;font-size:12px;height:0"},
        {"style": "color:#fff;background:#000 url(x.png) no-repeat"},
        {"style": "color:#333;background-color:transparent"},
        {"style": "opacity:abc"},
    ],
)
def test_visible_frames(attributes: dict[str, str]) -> None:
    assert child_frame("div", attributes, ROOT).hidden is None


def test_hidden_state_is_inherited_but_colour_can_be_reset() -> None:
    hidden = child_frame("div", {"style": "display:none"}, ROOT)
    assert child_frame("p", {"style": "display:block"}, hidden).hidden == "display:none"
    white = child_frame("div", {"style": "color:white"}, ROOT)
    assert child_frame("span", {"style": "color:black"}, white).hidden is None
    dark = child_frame("td", {"bgcolor": "#000000"}, ROOT)
    assert child_frame("font", {"color": "white"}, dark).hidden is None


def test_extractor_separates_hidden_text_and_comments() -> None:
    content = extract_html(
        "<p>Hello</p><div style='display:none'><p>one</p><p>two</p></div>"
        "<!-- note to the scanner --><!--[if mso]><table><![endif]-->"
        "<table bgcolor='#FFF'><tr><td><font color='white'>white text</font></td>"
        "<td>visible cell</td></tr></table><p>Bye</p><div style='opacity:0'>again</div>"
        "<span style='font-size:0'>tiny <b>bold</b></span>"
    )
    assert content.text == "Hello\n\nvisible cell\n\nBye"
    assert [(item.reason, item.text) for item in content.hidden] == [
        ("display:none", "one two"),
        ("HTML comment", "note to the scanner"),
        ("text the same colour as its background", "white text"),
        ("opacity:0", "again"),
        ("zero or one pixel font size", "tiny bold"),
    ]


def test_end_tags_close_back_to_their_element() -> None:
    content = extract_html("<div style='display:none'><p>gone</div><p>back</p></span>")
    assert content.text == "back"
    assert content.hidden[0].text == "gone"


def test_self_closing_non_void_tags_stay_open_like_in_browsers() -> None:
    content = extract_html("<div style='display:none'/>still hidden")
    assert content.text == ""
    assert content.hidden[0].text == "still hidden"


def test_hidden_segments_are_capped() -> None:
    html = "".join(f"<p>v{n}</p><div hidden>h{n}</div>" for n in range(60))
    assert len(extract_html(html).hidden) == 50
