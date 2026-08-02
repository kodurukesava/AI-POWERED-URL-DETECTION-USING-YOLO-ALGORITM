from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

try:
    import whois
except Exception:  # pragma: no cover
    whois = None

FEATURE_NAMES = [
    "having_ip_address",
    "url_length",
    "shortining_service",
    "having_at_symbol",
    "double_slash_redirecting",
    "prefix_suffix",
    "having_sub_domain",
    "sslfinal_state",
    "domain_registration_length",
    "favicon",
    "port",
    "https_token",
    "request_url",
    "url_of_anchor",
    "links_in_tags",
    "sfh",
    "submitting_to_email",
    "abnormal_url",
    "redirect",
    "on_mouseover",
    "rightclick",
    "popupwindow",
    "iframe",
    "age_of_domain",
    "dnsrecord",
    "web_traffic",
    "page_rank",
    "google_index",
    "links_pointing_to_page",
    "statistical_report",
]

SHORTENER_HINTS = (
    "bit.ly",
    "tinyurl",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "rebrand.ly",
    "cutt.ly",
    "shorturl",
)

SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "update",
    "billing",
    "wallet",
    "bank",
    "support",
    "unlock",
    "confirm",
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0 Safari/537.36"
)


def normalize_url(url: str) -> str:
    text = (url or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    return text


def _safe_int(value: str | None, default: int = 0) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def _hostname(url: str) -> str:
    return urlparse(url).hostname or ""


def _registrable_domain(hostname: str) -> str:
    parts = [part for part in hostname.split(".") if part]
    if len(parts) <= 2:
        return hostname
    return ".".join(parts[-2:])


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _domain_in_shortener(hostname: str) -> bool:
    return any(hint in hostname for hint in SHORTENER_HINTS)


def _tri_from_thresholds(value: float, good: float, bad: float, reverse: bool = False) -> int:
    if reverse:
        if value <= good:
            return 1
        if value <= bad:
            return 0
        return -1
    if value <= good:
        return 1
    if value <= bad:
        return 0
    return -1


def _value_from_ratio(ratio: float, low_good: float, mid_bad: float) -> int:
    if ratio <= low_good:
        return 1
    if ratio <= mid_bad:
        return 0
    return -1


def _to_date(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    if isinstance(value, list):
        for item in value:
            converted = _to_date(item)
            if converted is not None:
                return converted
    return None


@lru_cache(maxsize=256)
def _whois_dates(domain: str) -> tuple[datetime | None, datetime | None]:
    if whois is None or not domain:
        return None, None
    try:
        record = whois.whois(domain)
    except Exception:
        return None, None
    created = _to_date(getattr(record, "creation_date", None))
    expires = _to_date(getattr(record, "expiration_date", None))
    return created, expires


class PageInspector(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.base_host = _hostname(base_url)
        self.title = ""
        self.anchor_hrefs: list[str] = []
        self.resource_urls: list[str] = []
        self.link_hrefs: list[str] = []
        self.form_actions: list[str] = []
        self.iframe_srcs: list[str] = []
        self.favicon_hrefs: list[str] = []
        self.meta_refresh_contents: list[str] = []
        self.saw_on_mouseover = False
        self.saw_rightclick_disabled = False
        self.saw_popup = False
        self.saw_mailto = False
        self.saw_noindex = False
        self._capture_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()

        if "onmouseover" in attr_map:
            self.saw_on_mouseover = True
        if "oncontextmenu" in attr_map or "onmousedown" in attr_map:
            self.saw_rightclick_disabled = True

        if tag == "title":
            self._capture_title = True
        elif tag == "a":
            self.anchor_hrefs.append(attr_map.get("href", ""))
            if "mailto:" in attr_map.get("href", "").lower():
                self.saw_mailto = True
        elif tag in {"img", "script", "link", "iframe"}:
            src = attr_map.get("src") or attr_map.get("href") or ""
            if tag == "iframe":
                self.iframe_srcs.append(src)
            else:
                self.resource_urls.append(src)
                if tag == "link" and "icon" in attr_map.get("rel", "").lower():
                    self.favicon_hrefs.append(src)
        elif tag == "form":
            self.form_actions.append(attr_map.get("action", ""))
            if "mailto:" in attr_map.get("action", "").lower():
                self.saw_mailto = True
        elif tag == "meta":
            if attr_map.get("http-equiv", "").lower() == "refresh":
                self.meta_refresh_contents.append(attr_map.get("content", ""))
            if "noindex" in attr_map.get("name", "").lower() or "noindex" in attr_map.get("content", "").lower():
                self.saw_noindex = True

        combined_attrs = " ".join(f"{key}={value}" for key, value in attr_map.items())
        if "window.open" in combined_attrs.lower() or "popup" in combined_attrs.lower() or "alert(" in combined_attrs.lower():
            self.saw_popup = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._capture_title = False

    def handle_data(self, data: str) -> None:
        if self._capture_title:
            self.title += data.strip()

    def close(self) -> None:
        super().close()


@dataclass(frozen=True)
class URLFeatureSet:
    values: list[int]
    mapping: dict[str, int]
    fetch_error: str | None = None
    final_url: str | None = None


def _fetch_page(url: str) -> tuple[requests.Response | None, str | None]:
    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        return response, None
    except Exception as exc:  # pragma: no cover
        return None, str(exc)


def _resource_host(resource: str, base_url: str) -> str:
    if not resource:
        return ""
    absolute = urljoin(base_url, unescape(resource.strip()))
    return _hostname(absolute)


def _is_internal(resource_host: str, base_host: str) -> bool:
    if not resource_host:
        return True
    if resource_host == base_host:
        return True
    return resource_host.endswith("." + base_host) or base_host.endswith("." + resource_host)


def _ratio_external(resources: list[str], base_url: str) -> float:
    if not resources:
        return 0.0
    base_host = _hostname(base_url)
    external = 0
    total = 0
    for resource in resources:
        if not resource:
            continue
        total += 1
        resource_host = _resource_host(resource, base_url)
        if resource_host and not _is_internal(resource_host, base_host):
            external += 1
    return external / max(1, total)


def _anchor_ratio(anchor_hrefs: list[str], base_url: str) -> float:
    if not anchor_hrefs:
        return 0.0
    base_host = _hostname(base_url)
    external = 0
    total = 0
    for href in anchor_hrefs:
        href = (href or "").strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
            continue
        total += 1
        if href.lower().startswith("mailto:"):
            external += 1
            continue
        resource_host = _resource_host(href, base_url)
        if resource_host and not _is_internal(resource_host, base_host):
            external += 1
    return external / max(1, total)


def _links_in_tags_ratio(resources: list[str], base_url: str) -> float:
    return _ratio_external(resources, base_url)


def _sfh_value(form_actions: list[str], base_url: str) -> int:
    if not form_actions:
        return 1
    base_host = _hostname(base_url)
    external = 0
    blank = 0
    for action in form_actions:
        cleaned = (action or "").strip()
        if not cleaned or cleaned.lower() in {"about:blank", "javascript:void(0)", "#"}:
            blank += 1
            continue
        action_host = _resource_host(cleaned, base_url)
        if action_host and not _is_internal(action_host, base_host):
            external += 1
    if external > 0:
        return -1
    if blank > 0:
        return 0
    return 1


def _favicon_value(favicon_hrefs: list[str], base_url: str) -> int:
    if not favicon_hrefs:
        return 0
    base_host = _hostname(base_url)
    favicon_host = _resource_host(favicon_hrefs[0], base_url)
    if not favicon_host:
        return 0
    return 1 if _is_internal(favicon_host, base_host) else -1


def _safe_days_between(start: datetime | None, end: datetime | None) -> int | None:
    if not start or not end:
        return None
    return max(0, (end.date() - start.date()).days)


def _domain_age_value(domain: str) -> tuple[int, int]:
    return 0, 0


def _dnsrecord_value(hostname: str) -> int:
    try:
        socket.gethostbyname_ex(hostname)
        return 1
    except Exception:
        return -1


def extract_url_features(url: str, fetch_page: bool = False) -> URLFeatureSet:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""
    domain = _registrable_domain(hostname)
    path = parsed.path or ""
    query = parsed.query or ""
    lower_url = normalized.lower()
    url_length = len(normalized)
    url_host = hostname.lower()
    is_ip = _is_ip(hostname)
    subdomain_count = max(0, len([part for part in hostname.split(".") if part]) - 2)
    port_value = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

    dns_value = _dnsrecord_value(hostname) if hostname else -1
    age_value, registration_value = _domain_age_value(domain)

    fetch_error = None
    final_url = normalized
    same_host = True
    redirect_value = 0
    anchor_ratio = 0.0
    request_ratio = 0.0
    links_ratio = 0.0
    links_pointing_value = 0
    form_value = 0
    favicon_value = 0
    submitting_email = 1
    on_mouseover = 1
    rightclick = 1
    popupwindow = 1
    iframe_value = 1
    web_traffic_value = 0
    page_rank_value = 0
    google_index_value = 0
    statistical_value = 1

    if fetch_page:
        response, fetch_error = _fetch_page(normalized)
        html_text = ""
        inspector: PageInspector | None = None
        if response is not None:
            final_url = response.url or normalized
            html_text = response.text or ""
            inspector = PageInspector(final_url)
            try:
                inspector.feed(html_text[:200000])
                inspector.close()
            except Exception:
                inspector = None

            final_hostname = _hostname(final_url) or hostname
            same_host = final_hostname == hostname or final_hostname.endswith("." + hostname) or hostname.endswith("." + final_hostname)

            history_count = len(response.history)
            if history_count == 0:
                redirect_value = 1
            elif history_count == 1:
                redirect_value = 0
            else:
                redirect_value = -1

            if inspector and inspector.meta_refresh_contents:
                redirect_value = min(redirect_value, 0)

            anchor_ratio = _anchor_ratio(inspector.anchor_hrefs, final_url) if inspector else 0.0
            request_ratio = _ratio_external(inspector.resource_urls, final_url) if inspector else 0.0
            links_ratio = _links_in_tags_ratio(inspector.link_hrefs, final_url) if inspector else 0.0
            total_links = 0
            internal_links = 0
            if inspector:
                for href in inspector.anchor_hrefs:
                    cleaned = (href or "").strip()
                    if not cleaned or cleaned.startswith("#"):
                        continue
                    total_links += 1
                    resource_host = _resource_host(cleaned, final_url)
                    if not resource_host or _is_internal(resource_host, final_hostname):
                        internal_links += 1

            if total_links == 0:
                links_pointing_value = 0
            else:
                internal_ratio = internal_links / total_links
                links_pointing_value = 1 if internal_ratio >= 0.75 and total_links >= 10 else 0 if internal_ratio >= 0.4 else -1

            form_value = _sfh_value(inspector.form_actions, final_url) if inspector else 0
            favicon_value = _favicon_value(inspector.favicon_hrefs, final_url) if inspector else 0
            submitting_email = -1 if inspector and inspector.saw_mailto else 1
            on_mouseover = -1 if inspector and inspector.saw_on_mouseover else 1
            rightclick = -1 if inspector and inspector.saw_rightclick_disabled else 1
            popupwindow = -1 if inspector and inspector.saw_popup else 1
            iframe_value = -1 if inspector and inspector.iframe_srcs else 1

            web_traffic_value = 1 if len(html_text) > 1500 else 0
            page_rank_value = 1 if (not is_ip and subdomain_count <= 1 and len(domain) <= 18 and "-" not in domain) else 0 if not is_ip else -1
            google_index_value = -1 if inspector and inspector.saw_noindex else 1

            suspicious_keyword_hits = sum(keyword in lower_url for keyword in SUSPICIOUS_KEYWORDS)
            if suspicious_keyword_hits >= 2:
                statistical_value = -1
            if any(marker in lower_url for marker in ("login", "verify", "password")) and parsed.scheme.lower() != "https":
                statistical_value = -1
            if request_ratio > 0.6 or anchor_ratio > 0.6 or links_ratio > 0.6:
                statistical_value = -1
            if inspector and inspector.saw_popup:
                statistical_value = -1
        else:
            fetch_error = fetch_error or "Page fetch failed"
            web_traffic_value = -1
            page_rank_value = 0
            google_index_value = 0

    values = {
        "having_ip_address": -1 if is_ip else 1,
        "url_length": _tri_from_thresholds(url_length, good=54, bad=75),
        "shortining_service": -1 if _domain_in_shortener(url_host) else 1,
        "having_at_symbol": -1 if "@" in normalized else 1,
        "double_slash_redirecting": -1 if path.startswith("//") or "//" in normalized.split("://", 1)[-1] else 1,
        "prefix_suffix": -1 if "-" in domain else 1,
        "having_sub_domain": 1 if subdomain_count <= 1 else 0 if subdomain_count == 2 else -1,
        "sslfinal_state": 1 if parsed.scheme.lower() == "https" else -1,
        "domain_registration_length": registration_value,
        "favicon": favicon_value,
        "port": 1 if port_value in {80, 443} else -1,
        "https_token": -1 if "https" in url_host and parsed.scheme.lower() != "https" else 1,
        "request_url": _value_from_ratio(request_ratio, low_good=0.22, mid_bad=0.61),
        "url_of_anchor": _value_from_ratio(anchor_ratio, low_good=0.31, mid_bad=0.67),
        "links_in_tags": _value_from_ratio(links_ratio, low_good=0.17, mid_bad=0.81),
        "sfh": form_value,
        "submitting_to_email": submitting_email,
        "abnormal_url": -1 if not same_host else 1,
        "redirect": redirect_value,
        "on_mouseover": on_mouseover,
        "rightclick": rightclick,
        "popupwindow": popupwindow,
        "iframe": iframe_value,
        "age_of_domain": age_value,
        "dnsrecord": dns_value,
        "web_traffic": web_traffic_value,
        "page_rank": page_rank_value,
        "google_index": google_index_value,
        "links_pointing_to_page": links_pointing_value,
        "statistical_report": statistical_value,
    }

    return URLFeatureSet(
        values=[values[name] for name in FEATURE_NAMES],
        mapping=values,
        fetch_error=fetch_error,
        final_url=final_url,
    )


def url_risk_reason(features: dict[str, int]) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []

    if features["having_ip_address"] == -1:
        score += 0.28
        reasons.append("Uses an IP address instead of a normal domain")
    if features["shortining_service"] == -1:
        score += 0.16
        reasons.append("Looks like a URL shortener or redirect service")
    if features["having_at_symbol"] == -1:
        score += 0.22
        reasons.append("Contains an @ symbol, which is a common phishing trick")
    if features["double_slash_redirecting"] == -1:
        score += 0.12
        reasons.append("Contains suspicious double-slash redirecting")
    if features["prefix_suffix"] == -1:
        score += 0.08
        reasons.append("Uses a hyphenated domain name")
    if features["having_sub_domain"] == -1:
        score += 0.12
        reasons.append("Has many subdomains")
    if features["sslfinal_state"] == -1:
        score += 0.12
        reasons.append("Does not use HTTPS")
    if features["https_token"] == -1:
        score += 0.12
        reasons.append("Misuses https-looking text in the URL")
    if features["request_url"] == -1:
        score += 0.08
        reasons.append("Loads many external resources")
    if features["url_of_anchor"] == -1:
        score += 0.10
        reasons.append("Most links on the page point outside the site")
    if features["sfh"] == -1:
        score += 0.10
        reasons.append("Suspicious form submission target")
    if features["submitting_to_email"] == -1:
        score += 0.10
        reasons.append("Submits form data to email")
    if features["abnormal_url"] == -1:
        score += 0.16
        reasons.append("Redirects to a different host")
    if features["redirect"] == -1:
        score += 0.10
        reasons.append("Uses multiple redirects")
    if features["popupwindow"] == -1:
        score += 0.08
        reasons.append("Uses popup-style scripting")
    if features["iframe"] == -1:
        score += 0.08
        reasons.append("Contains iframes, which are often used for deception")
    if features["age_of_domain"] == -1:
        score += 0.10
        reasons.append("Domain appears very new or unavailable")
    if features["dnsrecord"] == -1:
        score += 0.14
        reasons.append("Domain DNS record could not be resolved")
    if features["web_traffic"] == -1:
        score += 0.08
        reasons.append("Page content could not be retrieved reliably")
    if features["page_rank"] == -1:
        score += 0.05
    if features["google_index"] == -1:
        score += 0.05
    if features["links_pointing_to_page"] == -1:
        score += 0.06
    if features["statistical_report"] == -1:
        score += 0.12
        reasons.append("Multiple suspicious signals were detected together")

    return min(1.0, score), reasons
