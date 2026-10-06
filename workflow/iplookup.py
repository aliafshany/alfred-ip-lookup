#!/usr/bin/python3
"""Alfred IP Lookup. Filter mode prints Script Filter JSON and never hits the network.

Fetch mode (--fetch) queries every source at once through /usr/bin/curl.
"""

from __future__ import annotations

import datetime
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

CURL = "/usr/bin/curl"
USER_AGENT = "Mozilla/5.0"
SOURCE_CAP_S = 8
CURL_MAX_S = 6
FRESH_OK_S = 6 * 3600
FRESH_FAIL_S = 5 * 60
BOOTSTRAP_S = 30 * 86400
PRUNE_S = 7 * 86400
RUNNING_S = 30
RERUN_S = 0.2

# File key, waiting-row label.
SOURCES = (
    ("check-host", "check-host"),
    ("ip-api", "ip-api.com"),
    ("ipapi-is", "ipapi.is"),
    ("ipwho-is", "ipwho.is"),
    ("ipinfo", "ipinfo.io"),
    ("rdap", "RDAP"),
)

CGNAT = ipaddress.ip_network("100.64.0.0/10")

CODE_TO_NAME = {
    "US": "United States",
    "CA": "Canada",
    "MX": "Mexico",
    "BR": "Brazil",
    "AR": "Argentina",
    "CL": "Chile",
    "CO": "Colombia",
    "PE": "Peru",
    "VE": "Venezuela",
    "GB": "United Kingdom",
    "IE": "Ireland",
    "FR": "France",
    "DE": "Germany",
    "NL": "Netherlands",
    "BE": "Belgium",
    "LU": "Luxembourg",
    "CH": "Switzerland",
    "AT": "Austria",
    "IT": "Italy",
    "ES": "Spain",
    "PT": "Portugal",
    "SE": "Sweden",
    "NO": "Norway",
    "DK": "Denmark",
    "FI": "Finland",
    "IS": "Iceland",
    "PL": "Poland",
    "CZ": "Czechia",
    "SK": "Slovakia",
    "HU": "Hungary",
    "RO": "Romania",
    "BG": "Bulgaria",
    "GR": "Greece",
    "UA": "Ukraine",
    "RU": "Russia",
    "BY": "Belarus",
    "KZ": "Kazakhstan",
    "TR": "Turkey",
    "IR": "Iran",
    "IQ": "Iraq",
    "IL": "Israel",
    "SA": "Saudi Arabia",
    "AE": "United Arab Emirates",
    "QA": "Qatar",
    "KW": "Kuwait",
    "OM": "Oman",
    "BH": "Bahrain",
    "JO": "Jordan",
    "LB": "Lebanon",
    "EG": "Egypt",
    "ZA": "South Africa",
    "NG": "Nigeria",
    "KE": "Kenya",
    "MA": "Morocco",
    "DZ": "Algeria",
    "TN": "Tunisia",
    "IN": "India",
    "PK": "Pakistan",
    "BD": "Bangladesh",
    "CN": "China",
    "JP": "Japan",
    "KR": "South Korea",
    "TW": "Taiwan",
    "HK": "Hong Kong",
    "SG": "Singapore",
    "MY": "Malaysia",
    "TH": "Thailand",
    "VN": "Vietnam",
    "ID": "Indonesia",
    "PH": "Philippines",
    "AU": "Australia",
    "NZ": "New Zealand",
    "AF": "Afghanistan",
    "NP": "Nepal",
    "LK": "Sri Lanka",
    "MM": "Myanmar",
    "KH": "Cambodia",
    "LA": "Laos",
}

_ALIASES = {
    "united states of america": "US",
    "usa": "US",
    "us": "US",
    "america": "US",
    "uk": "GB",
    "great britain": "GB",
    "britain": "GB",
    "united kingdom": "GB",
    "russia": "RU",
    "russian federation": "RU",
    "iran": "IR",
    "islamic republic of iran": "IR",
    "iran, islamic republic of": "IR",
    "turkey": "TR",
    "türkiye": "TR",
    "turkiye": "TR",
    "uae": "AE",
    "united arab emirates": "AE",
    "czech republic": "CZ",
    "czechia": "CZ",
    "south korea": "KR",
    "korea, republic of": "KR",
    "republic of korea": "KR",
    "north korea": "KP",
    "vietnam": "VN",
    "viet nam": "VN",
    "taiwan": "TW",
    "hong kong": "HK",
    "the netherlands": "NL",
    "netherlands": "NL",
    "holland": "NL",
    "syria": "SY",
    "syrian arab republic": "SY",
    "venezuela": "VE",
    "venezuela, bolivarian republic of": "VE",
    "bolivia": "BO",
    "tanzania": "TZ",
    "united republic of tanzania": "TZ",
    "laos": "LA",
    "lao people's democratic republic": "LA",
    "moldova": "MD",
    "republic of moldova": "MD",
    "palestine": "PS",
    "state of palestine": "PS",
    "oman": "OM",
    "finland": "FI",
    "switzerland": "CH",
    "france": "FR",
    "germany": "DE",
    "deutschland": "DE",
}

NAME_TO_CODE = {}
for _code, _name in CODE_TO_NAME.items():
    NAME_TO_CODE[_name.casefold()] = _code
NAME_TO_CODE.update(_ALIASES)

_ISP_DROP = {
    "limited",
    "ltd",
    "llc",
    "inc",
    "gmbh",
    "ag",
    "bv",
    "co",
    "company",
    "corporation",
}

_IPV4_RE = re.compile(
    r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"
)
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}:|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|"
    r"[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|"
    r":(?::[0-9A-Fa-f]{1,4}){1,7}|"
    r"::"
    r")(?![0-9A-Fa-f:])",
    re.IGNORECASE,
)
_HOST_RE = re.compile(
    r"\b((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})\b"
)
_ROW_RE = re.compile(r"<tr>\s*<td>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*</tr>", re.S | re.I)
_TITLE_RE = re.compile(r'<a href="#ip_info-[^"]*">\s*(.*?)\s*</a>', re.S | re.I)
_DATE_RE = re.compile(r"^(.*?)\s*\((\d{2})\.(\d{2})\.(\d{4})\)\s*$")
_PRIVATE_CUSTOMER_RE = re.compile(r"\(\s*private\s+customer\s*\)", re.I)
_AS_PREFIX_RE = re.compile(r"^as\d+\s+", re.I)
_AS_FIELD_RE = re.compile(r"^AS\s*(\d+)\s*(.*)$", re.I)
_PUNCT_RE = re.compile(r"[^\w\s]", re.UNICODE)


def cache_root():
    env = os.environ.get("alfred_workflow_cache")
    if env:
        return env
    return os.path.expanduser(
        "~/Library/Caches/com.runningwithcrayons.Alfred/Workflow Data/com.aliafshany.ip-lookup"
    )


def ip_safe(ip):
    return str(ip).replace(":", "_").replace("/", "_").replace("%", "_")


def host_safe(host):
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    return cleaned[:180] or "host"


def lookup_dir(ip):
    return os.path.join(cache_root(), "lookups", ip_safe(ip))


def normalize_digits(text):
    out = []
    for ch in text:
        code = ord(ch)
        if 0x06F0 <= code <= 0x06F9:
            out.append(chr(ord("0") + code - 0x06F0))
        elif 0x0660 <= code <= 0x0669:
            out.append(chr(ord("0") + code - 0x0660))
        else:
            out.append(ch)
    return "".join(out)


def is_nonpublic(addr):
    if addr.version == 4 and addr in CGNAT:
        return True
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return True
    if addr.is_global is False:
        return True
    return False


def extract_ip(text):
    found = []
    for match in _IPV4_RE.finditer(text):
        token = match.group(0)
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        found.append((match.start(), token))
    for match in _IPV6_RE.finditer(text):
        token = match.group(0)
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        found.append((match.start(), token))
    if not found:
        return None
    found.sort(key=lambda item: item[0])
    return str(ipaddress.ip_address(found[0][1]))


def looks_incomplete(text):
    stripped = text.strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){0,2}\.?", stripped):
        return True
    if re.fullmatch(r"(?:\d{1,3}\.){1,3}", stripped):
        return True
    if re.search(r"(?:^|[^\d])(\d{1,3}(?:\.\d{1,3}){0,2}\.)(?:$|[^\d])", stripped):
        return True
    if ":" in stripped and re.fullmatch(r"[0-9A-Fa-f:]+", stripped):
        return True
    return False


def parse_query(text):
    raw = text or ""
    norm = normalize_digits(raw).strip()
    if not norm:
        return {"kind": "empty", "ip": None, "host": None}
    ip_text = extract_ip(norm)
    if ip_text:
        addr = ipaddress.ip_address(ip_text)
        kind = "private" if is_nonpublic(addr) else "ip"
        return {"kind": kind, "ip": str(addr), "host": None}
    if looks_incomplete(norm):
        return {"kind": "incomplete", "ip": None, "host": None}
    if re.search(r"[A-Za-z]", norm) and "." in norm:
        match = _HOST_RE.search(norm)
        if match:
            return {"kind": "host", "ip": None, "host": match.group(1)}
    return {"kind": "incomplete", "ip": None, "host": None}


def flag_emoji(code):
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)


def isp_key(name):
    text = (name or "").casefold()
    text = _PRIVATE_CUSTOMER_RE.sub(" ", text)
    text = text.strip()
    while True:
        updated = _AS_PREFIX_RE.sub("", text)
        if updated == text:
            break
        text = updated.strip()
    text = _PUNCT_RE.sub("", text)
    tokens = [tok for tok in text.split() if tok not in _ISP_DROP and not re.fullmatch(r"as\d+", tok)]
    return " ".join(tokens)


def isp_group_key(rec):
    asn = str(rec.get("asn") or "").strip()
    asn = re.sub(r"^AS", "", asn, flags=re.I)
    if asn.isdigit():
        return "asn:" + asn
    name = isp_key(rec.get("isp") or "")
    if name:
        return "name:" + name
    return ""


def display_isp(name):
    return re.sub(r"^AS\d+\s+", "", (name or "").strip(), flags=re.I).strip()


def split_as(value):
    text = str(value or "").strip()
    match = _AS_FIELD_RE.match(text)
    if match:
        return match.group(1), match.group(2).strip()
    found = re.search(r"\bAS(\d+)\b", text, re.I)
    if found:
        rest = re.sub(r"\bAS\d+\b", "", text, flags=re.I).strip(" -")
        return found.group(1), rest
    if text.isdigit():
        return text, ""
    return "", text


def _clean_html(fragment):
    text = re.sub(r"<[^>]+>", " ", fragment or "")
    text = html.unescape(text).replace("\xa0", " ")
    return re.sub(r"\s+", " ", text).strip()


def _split_country(value):
    value = (value or "").strip()
    match = re.match(r"^(.*?)\s*\(([A-Za-z]{2})\)\s*$", value)
    if match:
        return match.group(1).strip(), match.group(2).upper()
    return value, ""


def parse_checkhost(page):
    marker = '<div class="ipinfo-item mb-3" id="ip_info-'
    starts = []
    pos = 0
    while True:
        found = page.find(marker, pos)
        if found < 0:
            break
        starts.append(found)
        pos = found + len(marker)
    records = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(page)
        rec = _parse_checkhost_block(page[start:end])
        if rec:
            records.append(rec)
    return records


def _parse_checkhost_block(block):
    id_match = re.search(r'id="ip_info-([^"]+)"', block)
    key = id_match.group(1) if id_match else ""
    title_match = _TITLE_RE.search(block)
    title = _clean_html(title_match.group(1)) if title_match else key
    name = title
    date_obj = None
    date_text = ""
    date_match = _DATE_RE.match(title)
    if date_match:
        name = date_match.group(1).strip()
        day = int(date_match.group(2))
        month = int(date_match.group(3))
        year = int(date_match.group(4))
        date_text = "%02d.%02d.%04d" % (day, month, year)
        try:
            date_obj = datetime.date(year, month, day)
        except ValueError:
            date_obj = None
    fields = {}
    for row in _ROW_RE.finditer(block):
        label = _clean_html(row.group(1))
        if label in fields:
            continue
        fields[label] = _clean_html(row.group(2))
    country_name, country_code = _split_country(fields.get("Country", ""))
    asn_digits = re.sub(r"\D", "", fields.get("ASN", ""))
    label = "%s (%s)" % (name, date_text) if date_text else name
    return {
        "key": key,
        "name": name,
        "date": date_obj,
        "label": label,
        "asn": asn_digits,
        "isp": fields.get("ISP / Org", ""),
        "country": country_name,
        "country_code": country_code,
        "region": fields.get("Region", ""),
        "city": fields.get("City", ""),
        "source": "check-host",
    }


def enrich_countries(records):
    seen = {}
    for rec in records:
        name = (rec.get("country") or "").strip()
        code = (rec.get("country_code") or "").strip().upper()
        if name and code:
            seen[name.casefold()] = code
    for rec in records:
        name = (rec.get("country") or "").strip()
        code = (rec.get("country_code") or "").strip().upper()
        if not code and name:
            code = seen.get(name.casefold()) or NAME_TO_CODE.get(name.casefold(), "")
        if code and not name:
            name = CODE_TO_NAME.get(code, "")
        rec["country"] = name
        rec["country_code"] = code
    return records


def _most_common(values):
    cleaned = [value.strip() for value in values if value and str(value).strip()]
    if not cleaned:
        return ""
    return Counter(cleaned).most_common(1)[0][0]


def build_summary(ip, records, host=None, self_label=False):
    """Consensus title, subtitle, and copy text. `records` are geo hits only."""
    rows = enrich_countries([dict(rec) for rec in records])
    country_groups = {}
    for rec in rows:
        code = rec.get("country_code") or ""
        if not code:
            continue
        country_groups.setdefault(code, []).append(rec.get("country") or CODE_TO_NAME.get(code) or code)
    country_total = sum(len(names) for names in country_groups.values())
    country_rank = sorted(country_groups.items(), key=lambda item: (-len(item[1]), item[0]))
    winner = country_rank[0][0] if country_rank else ""
    winner_count = len(country_rank[0][1]) if country_rank else 0

    isp_groups = {}
    for rec in rows:
        key = isp_group_key(rec)
        if not key:
            continue
        isp_groups.setdefault(key, []).append(rec)
    isp_total = sum(len(group) for group in isp_groups.values())
    isp_rank = sorted(isp_groups.items(), key=lambda item: (-len(item[1]), item[0]))
    isp_winner_recs = isp_rank[0][1] if isp_rank else []
    isp_winner_count = len(isp_winner_recs)
    isp_name = _most_common(display_isp(rec.get("isp") or "") for rec in isp_winner_recs)
    asn = ""
    if isp_rank and isp_rank[0][0].startswith("asn:"):
        asn = isp_rank[0][0].split(":", 1)[1]
    else:
        asn = _most_common(str(rec.get("asn") or "") for rec in isp_winner_recs)
        asn = re.sub(r"^AS", "", asn, flags=re.I)

    disagree = len(country_rank) > 1
    if winner:
        cname = _most_common(country_rank[0][1]) or CODE_TO_NAME.get(winner) or winner
        title = (flag_emoji(winner) + " " + cname).strip()
    else:
        title = "Unknown location"
    if isp_name:
        title = title + " · " + isp_name
    if disagree:
        title = "⚠️ " + title

    if country_total and winner_count == country_total and isp_winner_count == isp_total:
        agree_bit = "all %d sources agree" % max(country_total, isp_total)
    else:
        agree_bit = "country %s · ISP %s agree" % (
            "%d/%d" % (winner_count, country_total) if country_total else "—",
            "%d/%d" % (isp_winner_count, isp_total) if isp_total else "—",
        )
    bits = []
    if self_label:
        bits.append("Your public IP")
    if host:
        bits.append("%s → %s" % (host, ip))
    else:
        bits.append(ip)
    if asn:
        bits.append("AS" + asn)
    bits.append(agree_bit)
    subtitle = " · ".join(bits)

    if winner:
        place_name = _most_common(country_groups.get(winner) or []) or CODE_TO_NAME.get(winner) or winner
        place = "%s (%s)" % (place_name, winner)
    else:
        place = "Unknown"
    isp_arg = isp_name
    if asn:
        isp_arg = (isp_name + " (AS%s)" % asn).strip()
    if isp_arg:
        arg = "%s — %s — %s" % (ip, place, isp_arg)
    else:
        arg = "%s — %s" % (ip, place)
    return {"title": title, "subtitle": subtitle, "arg": arg, "winner": winner, "asn": asn}


def match_rdap(services, ip):
    """Longest-prefix match over an IANA RDAP bootstrap `services` array."""
    addr = ipaddress.ip_address(ip)
    best_len = -1
    best_url = None
    for entry in services or []:
        if not isinstance(entry, (list, tuple)) or len(entry) < 2:
            continue
        prefixes, urls = entry[0], entry[1]
        base = _prefer_https(urls)
        if not base:
            continue
        for prefix in prefixes or []:
            try:
                net = ipaddress.ip_network(str(prefix), strict=False)
            except ValueError:
                continue
            if net.version != addr.version or addr not in net:
                continue
            if net.prefixlen > best_len:
                best_len = net.prefixlen
                best_url = base
    return best_url


def _prefer_https(urls):
    if isinstance(urls, str):
        urls = [urls]
    https = [url for url in urls or [] if str(url).lower().startswith("https://")]
    if https:
        return https[0]
    if urls:
        return urls[0]
    return None


def rdap_query_url(base, ip):
    return str(base).rstrip("/") + "/ip/" + ip


def rir_name(url):
    host = urllib.parse.urlparse(str(url)).netloc.lower()
    for needle, label in (
        ("afrinic", "AFRINIC"),
        ("apnic", "APNIC"),
        ("arin", "ARIN"),
        ("lacnic", "LACNIC"),
        ("ripe", "RIPE"),
    ):
        if needle in host:
            return label
    return host or "RDAP"


def _vcard_fn(entity):
    card = entity.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2 or not isinstance(card[1], list):
        return ""
    for item in card[1]:
        if isinstance(item, list) and item and str(item[0]).lower() == "fn":
            value = item[-1]
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _walk_entities(obj):
    found = []
    for entity in obj.get("entities") or []:
        if isinstance(entity, dict):
            found.append(entity)
            found.extend(_walk_entities(entity))
    return found


def org_from_rdap(doc):
    entities = _walk_entities(doc)
    chosen = None
    for entity in entities:
        roles = [str(role).lower() for role in (entity.get("roles") or [])]
        if "registrant" in roles:
            chosen = entity
            break
    if chosen is None and entities:
        chosen = entities[0]
    if chosen is None:
        return ""
    name = _vcard_fn(chosen)
    # RIPE tags the maintainer (e.g. MNT-RSPN) as registrant; the holder is in remarks.
    if not name or re.search(r"(^|[-_])mnt([-_]|$)", name, re.I):
        for remark in doc.get("remarks") or []:
            if remark.get("title") in (None, "description") and remark.get("description"):
                return str(remark["description"][0]).strip()
    if name:
        return name
    for entity in _walk_entities(chosen):
        name = _vcard_fn(entity)
        if name:
            return name
    return ""


def cidr_of(doc, ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        addr = None
    nets = []
    for item in doc.get("cidr0_cidrs") or []:
        if not isinstance(item, dict):
            continue
        if "v4prefix" in item:
            text = "%s/%s" % (item.get("v4prefix"), item.get("length"))
        elif "v6prefix" in item:
            text = "%s/%s" % (item.get("v6prefix"), item.get("length"))
        else:
            continue
        try:
            nets.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    if not nets:
        return ""
    if addr is not None:
        holding = [net for net in nets if addr in net]
        if holding:
            nets = holding
    nets.sort(key=lambda net: net.prefixlen, reverse=True)
    return str(nets[0])


def rir_from_doc(doc, base):
    for link in doc.get("links") or []:
        if isinstance(link, dict) and link.get("rel") == "self" and link.get("href"):
            return rir_name(link["href"])
    port = str(doc.get("port43") or "").lower()
    for needle, label in (
        ("afrinic", "AFRINIC"),
        ("apnic", "APNIC"),
        ("arin", "ARIN"),
        ("lacnic", "LACNIC"),
        ("ripe", "RIPE"),
    ):
        if needle in port:
            return label
    return rir_name(base)


def _short_reason(text):
    lines = (text or "").strip().splitlines()
    reason = lines[-1] if lines else "error"
    reason = re.sub(r"^curl:\s*\(\d+\)\s*", "", reason)
    reason = re.sub(r"^curl:\s*", "", reason)
    reason = re.sub(r"\s+", " ", reason).strip()
    lowered = reason.lower()
    if "timed out" in lowered or "timeout" in lowered or "operation too slow" in lowered:
        return "timeout"
    return reason[:80] or "error"


def curl(url, max_time=CURL_MAX_S):
    cmd = [
        CURL,
        "-sS",
        "-L",
        "--compressed",
        "-m",
        str(max_time),
        "-A",
        USER_AGENT,
        "-w",
        "\n%{http_code}",
        "--",
        url,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=max_time + 2,
        )
    except subprocess.TimeoutExpired:
        return None, "timeout"
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace")
        return None, _short_reason(err or "curl %s" % proc.returncode)
    raw = proc.stdout.decode("utf-8", "replace")
    if "\n" in raw:
        body, code = raw.rsplit("\n", 1)
    else:
        body, code = raw, ""
    code = code.strip()
    if not code.isdigit() or not (200 <= int(code) < 300):
        return None, "HTTP %s" % (code or "?")
    return body, None


def _json_loads(body):
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _record_for_json(rec):
    out = dict(rec)
    if isinstance(out.get("date"), datetime.date):
        out["date"] = out["date"].isoformat()
    return out


def fetch_checkhost(ip):
    started = time.time()
    url = "https://check-host.net/ip-info?" + urllib.parse.urlencode({"host": ip})
    body, err = curl(url)
    elapsed = int((time.time() - started) * 1000)
    if err:
        return {"error": err, "elapsed_ms": elapsed}
    records = [_record_for_json(rec) for rec in parse_checkhost(body)]
    if not records:
        return {"error": "no records", "elapsed_ms": elapsed}
    for rec in records:
        rec["elapsed_ms"] = elapsed
    return {"ok": True, "elapsed_ms": elapsed, "records": records}


def fetch_ip_api(ip):
    started = time.time()
    quoted = urllib.parse.quote(ip, safe=":")
    url = (
        "http://ip-api.com/json/%s?fields=status,message,country,countryCode,city,isp,org,as"
        % quoted
    )
    body, err = curl(url)
    elapsed = int((time.time() - started) * 1000)
    if err:
        return {"error": err, "elapsed_ms": elapsed}
    data = _json_loads(body)
    if data is None:
        return {"error": "invalid JSON", "elapsed_ms": elapsed}
    if data.get("status") != "success":
        reason = data.get("message") or data.get("status") or "failed"
        return {"error": str(reason)[:80], "elapsed_ms": elapsed}
    asn, from_as = split_as(data.get("as"))
    isp = (data.get("isp") or "").strip() or from_as or (data.get("org") or "").strip()
    return {
        "ok": True,
        "label": "ip-api.com",
        "country": data.get("country") or "",
        "country_code": (data.get("countryCode") or "").upper(),
        "city": data.get("city") or "",
        "region": "",
        "isp": isp,
        "asn": asn,
        "elapsed_ms": elapsed,
    }


def _company_name(value):
    if isinstance(value, dict):
        return str(value.get("name") or "").strip()
    return str(value or "").strip()


def fetch_ipapi_is(ip):
    started = time.time()
    url = "https://api.ipapi.is/?" + urllib.parse.urlencode({"q": ip})
    body, err = curl(url)
    elapsed = int((time.time() - started) * 1000)
    if err:
        return {"error": err, "elapsed_ms": elapsed}
    data = _json_loads(body)
    if data is None:
        return {"error": "invalid JSON", "elapsed_ms": elapsed}
    if data.get("is_bogon"):
        return {"error": "bogon", "elapsed_ms": elapsed}
    asn, from_as = split_as(data.get("asn"))
    isp = from_as or _company_name(data.get("company"))
    return {
        "ok": True,
        "label": "ipapi.is",
        "country": data.get("country") or "",
        "country_code": "",
        "city": data.get("city") or "",
        "region": data.get("region") or "",
        "isp": isp,
        "asn": asn,
        "elapsed_ms": elapsed,
    }


def fetch_ipwho(ip):
    started = time.time()
    url = "https://ipwho.is/" + urllib.parse.quote(ip, safe=":")
    body, err = curl(url)
    elapsed = int((time.time() - started) * 1000)
    if err:
        return {"error": err, "elapsed_ms": elapsed}
    data = _json_loads(body)
    if data is None:
        return {"error": "invalid JSON", "elapsed_ms": elapsed}
    if not data.get("success", False):
        reason = data.get("message") or "failed"
        return {"error": str(reason)[:80], "elapsed_ms": elapsed}
    conn = data.get("connection") or {}
    asn_raw = conn.get("asn")
    asn = re.sub(r"^AS", "", str(asn_raw).strip(), flags=re.I) if asn_raw else ""
    if asn and not asn.isdigit():
        parsed, _rest = split_as(asn_raw)
        asn = parsed
    isp = str(conn.get("isp") or conn.get("org") or "").strip()
    return {
        "ok": True,
        "label": "ipwho.is",
        "country": data.get("country") or "",
        "country_code": (data.get("country_code") or "").upper(),
        "city": data.get("city") or "",
        "region": data.get("region") or "",
        "isp": isp,
        "asn": asn,
        "elapsed_ms": elapsed,
    }


def fetch_ipinfo(ip):
    started = time.time()
    url = "https://ipinfo.io/" + urllib.parse.quote(ip, safe=":") + "/json"
    body, err = curl(url)
    elapsed = int((time.time() - started) * 1000)
    if err:
        return {"error": err, "elapsed_ms": elapsed}
    data = _json_loads(body)
    if data is None:
        return {"error": "invalid JSON", "elapsed_ms": elapsed}
    if data.get("bogon"):
        return {"error": "bogon", "elapsed_ms": elapsed}
    if data.get("error"):
        message = data["error"]
        if isinstance(message, dict):
            message = message.get("message") or message.get("title") or "error"
        return {"error": str(message)[:80], "elapsed_ms": elapsed}
    asn, isp = split_as(data.get("org"))
    return {
        "ok": True,
        "label": "ipinfo.io (live)",
        "country": "",
        "country_code": (data.get("country") or "").upper(),
        "city": data.get("city") or "",
        "region": data.get("region") or "",
        "isp": isp,
        "asn": asn,
        "elapsed_ms": elapsed,
    }


def _bootstrap_path(kind):
    return os.path.join(cache_root(), "rdap", kind + ".json")


def load_bootstrap(kind):
    path = _bootstrap_path(kind)
    if os.path.isfile(path) and (time.time() - os.path.getmtime(path)) < BOOTSTRAP_S:
        data = _read_json(path)
        if isinstance(data, dict) and data.get("services"):
            return data
    url = "https://data.iana.org/rdap/%s.json" % kind
    body, err = curl(url)
    if body:
        data = _json_loads(body)
        if data and data.get("services"):
            atomic_write(path, data)
            return data
    stale = _read_json(path)
    if isinstance(stale, dict) and stale.get("services"):
        return stale
    raise RuntimeError(err or "bootstrap failed")


def fetch_rdap(ip):
    started = time.time()
    try:
        addr = ipaddress.ip_address(ip)
        kind = "ipv6" if addr.version == 6 else "ipv4"
        boot = load_bootstrap(kind)
        base = match_rdap(boot.get("services") or [], ip)
        if not base:
            return {"error": "no RIR", "elapsed_ms": int((time.time() - started) * 1000)}
        body, err = curl(rdap_query_url(base, ip))
        elapsed = int((time.time() - started) * 1000)
        if err:
            return {"error": err, "elapsed_ms": elapsed}
        doc = _json_loads(body)
        if doc is None:
            return {"error": "invalid JSON", "elapsed_ms": elapsed}
        if doc.get("errorCode"):
            reason = doc.get("title") or doc.get("errorCode") or "error"
            return {"error": str(reason)[:80], "elapsed_ms": elapsed}
        country = doc.get("country") if isinstance(doc.get("country"), str) else ""
        return {
            "ok": True,
            "kind": "rdap",
            "country": country.strip(),
            "name": doc.get("name") or "",
            "handle": doc.get("handle") or "",
            "org": org_from_rdap(doc),
            "cidr": cidr_of(doc, ip),
            "rir": rir_from_doc(doc, base),
            "elapsed_ms": elapsed,
        }
    except Exception as exc:
        return {"error": _short_reason(str(exc)), "elapsed_ms": int((time.time() - started) * 1000)}


def fetch_public_ip():
    for url in ("https://api.ipify.org", "https://ipinfo.io/ip"):
        body, err = curl(url)
        if not body:
            continue
        token = body.strip().split()
        if not token:
            continue
        try:
            addr = ipaddress.ip_address(token[0])
        except ValueError:
            continue
        if is_nonpublic(addr):
            continue
        return str(addr)
    return None


def resolve_host(host):
    socket.setdefaulttimeout(2)
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.timeout:
        return None, "timeout"
    except socket.gaierror:
        return None, "could not resolve"
    except OSError as exc:
        return None, _short_reason(str(exc))
    if not infos:
        return None, "could not resolve"
    ip = infos[0][4][0]
    # VPN clients in fake-IP mode answer from 198.18.0.0/15; ask public DNS instead.
    try:
        fake = ipaddress.ip_address(ip) in FAKE_IP_NET
    except ValueError:
        fake = False
    if fake:
        real = _resolve_doh(host)
        if real:
            return real, None
    return ip, None


FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")


def _resolve_doh(host):
    for rtype in ("A", "AAAA"):
        query = urllib.parse.urlencode({"name": host, "type": rtype})
        body, _err = curl("https://dns.google/resolve?" + query, max_time=4)
        data = _json_loads(body) if body else None
        for answer in (data or {}).get("Answer") or []:
            if answer.get("type") in (1, 28) and answer.get("data"):
                return answer["data"]
    return None


def atomic_write(path, obj):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = "%s.tmp.%s" % (path, os.getpid())
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _write_stamp(directory, name):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(str(time.time()))
    os.replace(tmp, path)


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def prune_old(root=None):
    root = root or cache_root()
    cutoff = time.time() - PRUNE_S
    for folder in ("lookups", "hosts"):
        base = os.path.join(root, folder)
        if not os.path.isdir(base):
            continue
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for name in names:
            path = os.path.join(base, name)
            try:
                if os.path.isdir(path) and os.stat(path).st_mtime < cutoff:
                    shutil.rmtree(path, ignore_errors=True)
            except OSError:
                continue


def _clear_results(directory):
    os.makedirs(directory, exist_ok=True)
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        if name == "started":
            continue
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass


def _run_workers(ip, directory):
    tasks = (
        ("check-host", fetch_checkhost),
        ("ip-api", fetch_ip_api),
        ("ipapi-is", fetch_ipapi_is),
        ("ipwho-is", fetch_ipwho),
        ("ipinfo", fetch_ipinfo),
        ("rdap", fetch_rdap),
    )
    written = set()
    lock = threading.Lock()

    def runner(name, func):
        try:
            result = func(ip)
        except Exception as exc:
            result = {"error": _short_reason(str(exc))}
        if not isinstance(result, dict):
            result = {"error": "bad result"}
        with lock:
            if name in written:
                return
            written.add(name)
            atomic_write(os.path.join(directory, name + ".json"), result)

    pool = ThreadPoolExecutor(max_workers=len(tasks))
    futures = [pool.submit(runner, name, func) for name, func in tasks]
    started = time.time()
    while True:
        if all(fut.done() for fut in futures):
            break
        if time.time() - started >= SOURCE_CAP_S:
            break
        time.sleep(0.02)
    with lock:
        for name, _func in tasks:
            if name not in written:
                written.add(name)
                atomic_write(os.path.join(directory, name + ".json"), {"error": "timeout"})
    _write_stamp(directory, "done")
    pool.shutdown(wait=False)


def run_ip(ip):
    directory = lookup_dir(ip)
    os.makedirs(directory, exist_ok=True)
    if not os.path.isfile(os.path.join(directory, "started")):
        _write_stamp(directory, "started")
    _clear_results(directory)
    _run_workers(ip, directory)


def run_self():
    root = os.path.join(cache_root(), "self")
    os.makedirs(root, exist_ok=True)
    if not os.path.isfile(os.path.join(root, "started")):
        _write_stamp(root, "started")
    ip = fetch_public_ip()
    if not ip:
        atomic_write(os.path.join(root, "ip.json"), {"error": "no public IP"})
        _write_stamp(root, "done")
        return
    os.makedirs(lookup_dir(ip), exist_ok=True)
    if not os.path.isfile(os.path.join(lookup_dir(ip), "started")):
        _write_stamp(lookup_dir(ip), "started")
    atomic_write(os.path.join(root, "ip.json"), {"ip": ip})
    run_ip(ip)
    _write_stamp(root, "done")


def run_host(host):
    root = os.path.join(cache_root(), "hosts", host_safe(host))
    os.makedirs(root, exist_ok=True)
    if not os.path.isfile(os.path.join(root, "started")):
        _write_stamp(root, "started")
    ip, err = resolve_host(host)
    if err or not ip:
        atomic_write(os.path.join(root, "resolved.json"), {"error": err or "could not resolve"})
        _write_stamp(root, "done")
        return
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        atomic_write(os.path.join(root, "resolved.json"), {"error": "bad address"})
        _write_stamp(root, "done")
        return
    if not os.path.isfile(os.path.join(lookup_dir(ip), "started")):
        os.makedirs(lookup_dir(ip), exist_ok=True)
        _write_stamp(lookup_dir(ip), "started")
    atomic_write(os.path.join(root, "resolved.json"), {"ip": ip, "host": host})
    _write_stamp(root, "done")
    if is_nonpublic(ipaddress.ip_address(ip)):
        return
    run_ip(ip)


def spawn_fetch(args):
    script = os.path.abspath(__file__)
    cmd = ["/usr/bin/python3", script, "--fetch"] + list(args)
    subprocess.Popen(
        cmd,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=os.path.dirname(script),
        close_fds=True,
    )


def fetch_running(directory):
    started = os.path.join(directory, "started")
    done = os.path.join(directory, "done")
    if not os.path.isfile(started):
        return False
    try:
        started_m = os.path.getmtime(started)
    except OSError:
        return False
    if os.path.isfile(done):
        try:
            if os.path.getmtime(done) >= started_m - 0.05:
                return False
        except OSError:
            pass
    return (time.time() - started_m) < RUNNING_S


def claim_fetch(directory):
    os.makedirs(directory, exist_ok=True)
    started = os.path.join(directory, "started")
    if os.path.isfile(started):
        if fetch_running(directory):
            return False
        try:
            os.remove(started)
        except OSError:
            return False
    try:
        fd = os.open(started, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return False
    os.write(fd, str(time.time()).encode("utf-8"))
    os.close(fd)
    return True


def _load_source_files(directory):
    files = {}
    for key, _label in SOURCES:
        path = os.path.join(directory, key + ".json")
        if not os.path.isfile(path):
            continue
        data = _read_json(path)
        if isinstance(data, dict):
            files[key] = data
    return files


def cache_fresh(directory, files):
    done = os.path.join(directory, "done")
    if not os.path.isfile(done) or len(files) < len(SOURCES):
        return False
    failed = False
    for key, _label in SOURCES:
        data = files.get(key)
        if not isinstance(data, dict) or data.get("error"):
            failed = True
            break
    try:
        age = time.time() - os.path.getmtime(done)
    except OSError:
        return False
    ttl = FRESH_FAIL_S if failed else FRESH_OK_S
    return age < ttl


def _done_recent(directory, ttl):
    done = os.path.join(directory, "done")
    if not os.path.isfile(done):
        return False
    try:
        return (time.time() - os.path.getmtime(done)) < ttl
    except OSError:
        return False


def checkhost_url(ip):
    return "https://check-host.net/ip-info?" + urllib.parse.urlencode({"host": ip})


def ipinfo_url(ip):
    return "https://ipinfo.io/" + urllib.parse.quote(ip, safe=":")


def icon_item(title, subtitle="", valid=False):
    return {
        "title": title,
        "subtitle": subtitle,
        "valid": valid,
        "icon": {"path": "icon.png"},
    }


def result_item(title, subtitle, arg, ip):
    return {
        "title": title,
        "subtitle": subtitle,
        "arg": arg,
        "valid": True,
        "autocomplete": ip,
        "quicklookurl": checkhost_url(ip),
        "icon": {"path": "icon.png"},
        "mods": {
            "cmd": {
                "arg": checkhost_url(ip),
                "subtitle": "Open on check-host",
                "valid": True,
            },
            "alt": {
                "arg": ipinfo_url(ip),
                "subtitle": "Open on ipinfo.io",
                "valid": True,
            },
        },
    }


def _geo_rows(files):
    geos = []
    failures = []
    rdap = None
    for key, label in SOURCES:
        if key not in files:
            continue
        data = files[key]
        if data.get("error"):
            failures.append((label, str(data.get("error") or "failed")))
            continue
        if key == "rdap":
            rdap = data
            continue
        if key == "check-host":
            elapsed = data.get("elapsed_ms")
            for rec in data.get("records") or []:
                if not isinstance(rec, dict):
                    continue
                item = dict(rec)
                if item.get("elapsed_ms") is None:
                    item["elapsed_ms"] = elapsed
                item.setdefault("label", item.get("name") or "check-host")
                geos.append(item)
            continue
        geos.append(dict(data))
    return geos, failures, rdap


def _source_title(rec, winner):
    code = rec.get("country_code") or ""
    place = rec.get("country") or CODE_TO_NAME.get(code) or code or "Unknown"
    head = (flag_emoji(code) + " " + place).strip()
    city = (rec.get("city") or "").strip()
    isp = display_isp(rec.get("isp") or "")
    left = head + " · " + city if city else head
    title = left + (" — " + isp if isp else "")
    if winner and code and code != winner:
        title = "⚠️ " + title
    return title


def _source_subtitle(rec):
    label = rec.get("label") or "source"
    asn = str(rec.get("asn") or "").strip()
    asn = re.sub(r"^AS", "", asn, flags=re.I)
    if asn:
        return "%s · AS%s" % (label, asn)
    return label


def _source_arg(ip, rec):
    code = rec.get("country_code") or ""
    place = rec.get("country") or CODE_TO_NAME.get(code) or "Unknown"
    if code:
        place = "%s (%s)" % (place, code)
    city = (rec.get("city") or "").strip()
    if city:
        place = place + ", " + city
    isp = display_isp(rec.get("isp") or "")
    asn = str(rec.get("asn") or "").strip()
    asn = re.sub(r"^AS", "", asn, flags=re.I)
    if asn:
        isp = (isp + " (AS%s)" % asn).strip()
    return "%s — %s — %s" % (ip, place, isp)


def _city_key(city):
    return re.sub(r"\s*\(.*?\)", "", city or "").strip().casefold()


SHORT_LABELS = {
    "IPGeolocation.io": "IPGeolocation",
    "MaxMind GeoIP": "MaxMind",
    "IPInfo.io": "ipinfo DB",
    "ipinfo.io (live)": "ipinfo",
    "ip-api.com": "ip-api",
}


def _short_label(label):
    label = re.sub(r"\s*\(\d{2}\.\d{2}\.\d{4}\)", "", label or "source").strip()
    return SHORT_LABELS.get(label, label)


def _group_item(ip, recs, winner, win_isp):
    """Row shows only what differs from the summary: the city, plus country/ISP if they disagree."""
    rep = dict(recs[0])
    rep["country"] = _most_common(rec.get("country") for rec in recs)
    rep["city"] = _most_common(re.sub(r"\s*\(.*?\)", "", rec.get("city") or "") for rec in recs)
    rep["isp"] = _most_common(display_isp(rec.get("isp") or "") for rec in recs)
    code = rep.get("country_code") or ""
    other_country = bool(winner and code and code != winner)
    other_isp = isp_group_key(rep) != win_isp
    parts = []
    if other_country:
        place = rep["country"] or CODE_TO_NAME.get(code) or code
        parts.append((flag_emoji(code) + " " + place).strip())
    if rep["city"]:
        parts.append(rep["city"])
    title = " · ".join(parts) or "—"
    if other_isp and rep["isp"]:
        title += " — " + rep["isp"]
    title = ("⚠️ " if other_country else "📍 ") + title
    labels = ", ".join(_short_label(rec.get("label")) for rec in recs)
    subtitle = "%d sources · %s" % (len(recs), labels) if len(recs) > 1 else labels
    asn = re.sub(r"^AS", "", str(rep.get("asn") or "").strip(), flags=re.I)
    if other_isp and asn:
        subtitle += " · AS" + asn
    return result_item(title, subtitle, _source_arg(ip, rep), ip)


def _registry_item(ip, rdap):
    raw_country = (rdap.get("country") or "").strip()
    code = ""
    if re.fullmatch(r"[A-Za-z]{2}", raw_country):
        code = raw_country.upper()
    elif raw_country:
        code = NAME_TO_CODE.get(raw_country.casefold(), "")
    netname = (rdap.get("name") or rdap.get("handle") or "").strip()
    org = (rdap.get("org") or "").strip()
    title = "📋 " + (org or netname or "Registered network")
    if code:
        title += " · " + (flag_emoji(code) + " " + code).strip()
    cidr = (rdap.get("cidr") or rdap.get("handle") or "").strip()
    rir = rdap.get("rir") or "RDAP"
    subtitle = " · ".join(bit for bit in ("Registry " + rir, netname, cidr) if bit)
    arg = "%s — registered to %s%s — %s" % (ip, org or netname, " (%s)" % code if code else "", " ".join(bit for bit in (netname, cidr) if bit))
    return result_item(title, subtitle, arg, ip)


def lookup_items(ip, host=None, self_label=False):
    directory = lookup_dir(ip)
    files = _load_source_files(directory)
    fresh = cache_fresh(directory, files)
    running = fetch_running(directory)
    if not fresh and not running:
        if claim_fetch(directory):
            spawn_fetch([ip])
            running = True
        files = _load_source_files(directory)
        fresh = cache_fresh(directory, files)
        running = fetch_running(directory)
    pending = [label for key, label in SOURCES if key not in files]
    geos, failures, rdap = _geo_rows(files)
    geos = enrich_countries(geos)
    items = []
    summary = None
    if geos:
        summary = build_summary(ip, geos, host=host, self_label=self_label)
        items.append(result_item(summary["title"], summary["subtitle"], summary["arg"], ip))
        winner = summary["winner"]

        def sort_key(rec):
            code = rec.get("country_code") or ""
            major = 0 if winner and code == winner else 1
            elapsed = rec.get("elapsed_ms")
            if not isinstance(elapsed, (int, float)):
                elapsed = 10 ** 9
            return (major, elapsed)

        # One row per distinct (country, city, network); sources that say the same
        # thing share a row. A row with no city (or no country) that matches the summary adds nothing.
        win_isp = _most_common(isp_group_key(rec) for rec in geos)
        groups = {}
        for rec in sorted(geos, key=sort_key):
            code = rec.get("country_code") or ""
            key = (code, _city_key(rec.get("city")), isp_group_key(rec))
            if not key[1] and code in (winner, "") and key[2] == win_isp:
                continue
            groups.setdefault(key, []).append(rec)
        ranked = sorted(
            groups.values(),
            key=lambda recs: (0 if winner and recs[0].get("country_code") == winner else 1, -len(recs)),
        )
        for recs in ranked:
            items.append(_group_item(ip, recs, winner, win_isp))
    if rdap:
        items.append(_registry_item(ip, rdap))
    for label, reason in failures:
        items.append(icon_item("✗ %s — %s" % (label, reason)))
    if not items and not pending:
        items.append(icon_item("Looking up %s…" % ip))
    if pending:
        items.append(icon_item("⏳ waiting: " + ", ".join(pending)))
    elif not geos and not failures and not rdap:
        items.append(icon_item("Looking up %s…" % ip))
    rerun = (not fresh) and (running or bool(pending))
    return items, rerun


def clipboard_text():
    try:
        proc = subprocess.run(
            ["/usr/bin/pbpaste"],
            capture_output=True,
            timeout=0.05,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.decode("utf-8", "replace")


def clipboard_ip():
    text = clipboard_text().strip()
    if not text or len(text) > 200:
        return None
    parsed = parse_query(text)
    if parsed["kind"] == "ip":
        return parsed["ip"]
    return None


def _clipboard_row(ip):
    item = icon_item("Clipboard: %s — ⇥ to look up" % ip)
    item["autocomplete"] = ip
    return item


def render_empty():
    root = os.path.join(cache_root(), "self")
    info = _read_json(os.path.join(root, "ip.json")) if os.path.isdir(root) else None
    ip = None
    err = None
    if isinstance(info, dict):
        if info.get("ip"):
            ip = str(info["ip"])
        elif info.get("error"):
            err = str(info["error"])
    items = []
    rerun = False
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None and not is_nonpublic(addr):
            items, rerun = lookup_items(ip, self_label=True)
        else:
            items = [icon_item("Private or reserved address — no public location")]
    elif err and _done_recent(root, FRESH_FAIL_S):
        items = [icon_item("✗ public IP — %s" % err)]
    else:
        if not fetch_running(root):
            if claim_fetch(root):
                spawn_fetch(["--self"])
        items = [
            icon_item("Looking up your public IP…"),
            icon_item("⏳ waiting: public IP"),
        ]
        rerun = True
    clip = clipboard_ip()
    if clip and clip != ip:
        items.append(_clipboard_row(clip))
    payload = {"items": items}
    if rerun:
        payload["rerun"] = RERUN_S
    return payload


def render_host(host):
    root = os.path.join(cache_root(), "hosts", host_safe(host))
    info = _read_json(os.path.join(root, "resolved.json")) if os.path.isdir(root) else None
    if isinstance(info, dict) and info.get("ip"):
        ip = str(info["ip"])
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"items": [icon_item("✗ %s — bad address" % host)]}
        if is_nonpublic(addr):
            return {
                "items": [
                    icon_item(
                        "Private or reserved address — no public location",
                        "%s → %s" % (host, ip),
                    )
                ]
            }
        items, rerun = lookup_items(ip, host=host)
        payload = {"items": items}
        if rerun:
            payload["rerun"] = RERUN_S
        return payload
    if isinstance(info, dict) and info.get("error") and _done_recent(root, FRESH_FAIL_S):
        return {"items": [icon_item("✗ %s — %s" % (host, info["error"]))]}
    if not fetch_running(root):
        if claim_fetch(root):
            spawn_fetch(["--host", host])
    return {
        "rerun": RERUN_S,
        "items": [
            icon_item("Resolving %s…" % host),
            icon_item("⏳ waiting: DNS"),
        ],
    }


def script_filter(query):
    parsed = parse_query(query)
    if parsed["kind"] == "incomplete":
        return {"items": [icon_item("Keep typing an IP…")]}
    if parsed["kind"] == "private":
        return {"items": [icon_item("Private or reserved address — no public location")]}
    if parsed["kind"] == "empty":
        return render_empty()
    if parsed["kind"] == "host":
        return render_host(parsed["host"])
    items, rerun = lookup_items(parsed["ip"])
    payload = {"items": items}
    if rerun:
        payload["rerun"] = RERUN_S
    return payload


def emit(payload):
    sys.stdout.buffer.write(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    sys.stdout.buffer.write(b"\n")


def fetch_main(args):
    prune_old()
    if not args or args[0] == "--self":
        run_self()
        return
    if args[0] == "--host" and len(args) > 1:
        run_host(args[1])
        return
    run_ip(args[0])


def main(argv):
    if len(argv) >= 2 and argv[1] == "--fetch":
        fetch_main(argv[2:])
        return 0
    query = argv[1] if len(argv) > 1 else ""
    emit(script_filter(query))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
