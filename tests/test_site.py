"""Website checks, run in CI and before every deploy (pages.yml): nothing is published unless they pass."""

from __future__ import annotations

import datetime as dt
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from foldward import __version__

SITE = Path(__file__).resolve().parent.parent / "site"
PAGES = sorted(SITE.glob("*.html"))
_MONTHS = ("January February March April May June July August September October November December").split()
_DATE = re.compile(r"\b(\d{1,2}) (" + "|".join(_MONTHS) + r") (20\d\d)\b")


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id"):
            self.ids.add(a["id"])
        for key in ("href", "src"):
            if a.get(key):
                self.links.append(a[key])


def _parse(page: Path) -> _Page:
    p = _Page()
    p.feed(page.read_text("utf-8"))
    return p


def _date(text: str) -> dt.date:
    d, month, year = text
    return dt.date(int(year), _MONTHS.index(month) + 1, int(d))


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_site_footer_shows_the_package_version_and_a_date(page):
    # AG-C06: a version bump without a rebuilt site fails here
    m = re.search(r'<p class="fineprint">Foldward ([0-9][0-9.]*) · ([^<]+)</p>', page.read_text("utf-8"))
    assert m, f"{page.name} has no version line in its footer"
    assert m.group(1) == __version__, f"{page.name} says {m.group(1)}, the package is {__version__}"
    assert _DATE.search(m.group(2)), f"{page.name}'s footer date isn't a date: {m.group(2)!r}"


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_site_pages_link_the_accessibility_statement(page):
    # AG-E03
    assert "accessibility.html" in _parse(page).links, f"{page.name} doesn't link the accessibility statement"


def test_site_accessibility_statement_exists_and_is_dated():
    text = (SITE / "accessibility.html").read_text("utf-8")
    assert "<h1" in text and "WCAG" in text
    assert _DATE.search(text)


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_site_internal_links_resolve(page):
    for link in _parse(page).links:
        if link.startswith(("http://", "https://", "mailto:", "data:")):
            continue
        target, _, anchor = link.partition("#")
        dest = SITE / target if target else page
        assert dest.exists(), f"{page.name} links to missing {target}"
        if anchor:
            assert anchor in _parse(dest).ids, f"{page.name} links to #{anchor}, which {dest.name} doesn't have"


def test_site_privacy_policy_is_dated_after_its_last_change_in_meaning():
    # AG-N06: the update check (31 Oct 2026) changed what the policy says, so its date must not be older
    m = re.search(r"This policy is dated ([^.]+)\.", (SITE / "privacy.html").read_text("utf-8"))
    assert m
    assert _date(_DATE.search(m.group(1)).groups()) >= dt.date(2026, 10, 31)


def test_site_marks_planned_partner_features_as_planned():
    # AG-C01 / AG-D02 / AG-E05: nothing calls the scan verdict or the egress block yet
    text = (SITE / "index.html").read_text("utf-8")
    for item in re.findall(r"<li>(.*?)</li>", text, flags=re.S):
        if "malware verdict" in item or ("egress" in item.lower() and "firewall" in item):
            assert "Planned" in item or "planned" in item, f"unmarked planned feature: {item!r}"
    assert "Defeating any one layer still leaves the next" not in text


def test_site_install_command_names_the_release_tag():
    # INT-06: install a released version, never whatever main holds that minute
    text = (SITE / "index.html").read_text("utf-8")
    assert f"Foldward@v{__version__}" in text
    assert "pip install -e" not in text
