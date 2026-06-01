import subprocess
import nmap
import shodan as shodan_api
from wakeonlan import send_magic_packet
from proxmoxer import ProxmoxAPI
from config import *

def tool_wake_pc() -> str:
    try:
        send_magic_packet(PC_MAC)
        return f"Magic packet sent to {PC_MAC}. PC should wake up shortly."
    except Exception as e:
        return f"WoL error: {e}"


def tool_list_vms() -> str:
    try:
        prox = ProxmoxAPI(PROXMOX_HOST, port=PROXMOX_PORT,
                          user=PROXMOX_USER, password=PROXMOX_PASSWORD, verify_ssl=False)
        vms = prox.nodes(PROXMOX_NODE).qemu.get()
        if not vms:
            return "No VMs found."
        lines = [f"VM {v['vmid']:>4}: {v['name']:<20} [{v['status']}]" for v in vms]
        return "\n".join(lines)
    except Exception as e:
        return f"Proxmox error: {e}"


def tool_vm_action(vmid: int, action: str) -> str:
    try:
        prox = ProxmoxAPI(PROXMOX_HOST, port=PROXMOX_PORT,
                          user=PROXMOX_USER, password=PROXMOX_PASSWORD, verify_ssl=False)
        vm = prox.nodes(PROXMOX_NODE).qemu(vmid)
        if action == "status":
            s = vm.status.current.get()
            return f"VM {vmid} ({s.get('name', '?')}) is currently {s['status']}."
        else:
            getattr(vm.status, action).post()
            return f"VM {vmid}: '{action}' command sent successfully."
    except Exception as e:
        return f"Error on VM {vmid}: {e}"

def tool_shodan_query(query_type: str, query: str) -> str:
    if not SHODAN_API_KEY:
        return "Shodan not configured. Set SHODAN_API_KEY in .env"
    try:
        api = shodan_api.Shodan(SHODAN_API_KEY)
        if query_type == "host":
            host = api.host(query)
            ports = ", ".join(str(p) for p in host.get("ports", []))
            vulns = ", ".join(host.get("vulns", {}).keys()) or "none found"
            org = host.get("org", "unknown")
            country = host.get("country_name", "unknown")
            return (
                f"IP: {query}\n"
                f"Org: {org} | {country}\n"
                f"Open ports: {ports or 'none'}\n"
                f"CVEs: {vulns}"
            )
        else:
            results = api.search(query)
            total = results["total"]
            lines = [f"Total results: {total}\n"]
            for r in results["matches"][:5]:
                ip = r.get("ip_str", "?")
                port = r.get("port", "?")
                org = r.get("org", "unknown")
                lines.append(f"  {ip}:{port} — {org}")
            return "\n".join(lines)
    except shodan_api.APIError as e:
        return f"Shodan error: {e}"

def tool_whois_lookup(domain: str) -> str:
    try:
        import whois
        w = whois.whois(domain)

        def fmt(val):
            if val is None:
                return "—"
            if isinstance(val, list):
                val = val[0]
            if hasattr(val, "strftime"):
                return val.strftime("%Y-%m-%d")
            return str(val)

        # Registrant info varies by TLD/registrar privacy
        registrant = (
            w.get("org") or
            w.get("registrant_org") or
            w.get("registrant") or
            "— (likely privacy protected)"
        )

        lines = [
            f"🌐 WHOIS: {domain}",
            f"📋 Registrant:  {registrant}",
            f"🏢 Registrar:   {fmt(w.get('registrar'))}",
            f"📅 Created:     {fmt(w.get('creation_date'))}",
            f"📅 Expires:     {fmt(w.get('expiration_date'))}",
            f"📅 Updated:     {fmt(w.get('updated_date'))}",
            f"🔒 Status:      {fmt(w.get('status'))}",
        ]

        ns = w.get("name_servers")
        if ns:
            if isinstance(ns, list):
                ns = [n.lower() for n in ns]
            else:
                ns = [ns.lower()]
            lines.append(f"🖥️  Nameservers: {', '.join(sorted(set(ns)))}")

        emails = w.get("emails")
        if emails:
            if isinstance(emails, str):
                emails = [emails]
            lines.append(f"📧 Emails:      {', '.join(set(emails))}")

        return "\n".join(lines)

    except Exception as e:
        return f"WHOIS error: {e}"


def tool_dns_lookup(
    domain: str,
    record_types: list[str] = None,
    subdomains: bool = False,
) -> str:
    import dns.resolver
    import requests

    types = record_types or ["A", "MX", "TXT", "NS"]
    lines = [f"🔍 DNS records for {domain}:\n"]

    for rtype in types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            vals = []
            for r in answers:
                if rtype == "MX":
                    vals.append(f"{r.preference} {r.exchange}")
                else:
                    vals.append(r.to_text().strip('"'))
            lines.append(f"  {rtype:6} {chr(10).join(f'       {v}' if i > 0 else v for i, v in enumerate(vals))}")
        except dns.resolver.NoAnswer:
            lines.append(f"  {rtype:6} — (no records)")
        except dns.resolver.NXDOMAIN:
            return f"Domain '{domain}' does not exist."
        except Exception as e:
            lines.append(f"  {rtype:6} — error: {e}")

    if subdomains:
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15,
                headers={"User-Agent": "Jarvis/1.0"},
            )
            if resp.status_code == 200:
                entries = resp.json()
                subs = set()
                for e in entries:
                    for name in e.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(domain) and name != domain:
                            subs.add(name)
                if subs:
                    lines.append(f"\n📜 Subdomains via crt.sh ({len(subs)} found):")
                    for s in sorted(subs)[:30]:
                        lines.append(f"  • {s}")
                    if len(subs) > 30:
                        lines.append(f"  … and {len(subs) - 30} more")
                else:
                    lines.append("\n📜 crt.sh: no subdomains found")
        except Exception as e:
            lines.append(f"\n📜 crt.sh error: {e}")

    return "\n".join(lines)

def tool_search_pdf(
    url: str,
    terms: list[str],
    fuzzy: bool = True,
    context_lines: int = 2,
) -> str:
    import re
    import io
    import requests
    import fitz
    import pdfplumber

    # ── Download ──────────────────────────────────────────────────────────────
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Jarvis/1.0)"},
            timeout=20,
        )
        if resp.status_code != 200:
            return f"Failed to fetch PDF: HTTP {resp.status_code}"
        pdf_bytes = resp.content
    except Exception as e:
        return f"Download error: {e}"

    lines_out = [f"🔍 Searching PDF: {url}",
                 f"   Terms: {', '.join(terms)}\n"]

    def matches(text: str, term: str) -> bool:
        if fuzzy:
            return term.lower() in text.lower()
        return term in text

    def highlight(text: str, term: str) -> str:
        """Wrap matched term in >> << markers."""
        pattern = re.compile(re.escape(term), re.IGNORECASE if fuzzy else 0)
        return pattern.sub(lambda m: f">>{m.group()}<<", text)

    total_hits = 0

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        # ── Text search ───────────────────────────────────────────────────────
        lines_out.append("━━ 📝 Text matches ━━")
        text_hits = 0

        for page_num in range(doc.page_count):
            page_text = doc[page_num].get_text()
            page_lines = page_text.splitlines()

            for term in terms:
                for i, line in enumerate(page_lines):
                    if matches(line, term):
                        text_hits += 1
                        total_hits += 1
                        # Grab surrounding context
                        start = max(0, i - context_lines)
                        end   = min(len(page_lines), i + context_lines + 1)
                        ctx   = page_lines[start:end]
                        lines_out.append(f"\n  📌 Page {page_num + 1} — '{term}':")
                        for j, ctx_line in enumerate(ctx):
                            ctx_line = ctx_line.strip()
                            if not ctx_line:
                                continue
                            if matches(ctx_line, term):
                                lines_out.append(f"  ▶ {highlight(ctx_line, term)}")
                            else:
                                lines_out.append(f"    {ctx_line}")

        if text_hits == 0:
            lines_out.append("  — no text matches found")

        doc.close()

        # ── Table search ──────────────────────────────────────────────────────
        lines_out.append("\n━━ 📊 Table matches ━━")
        table_hits = 0

        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page_num, page in enumerate(pdf.pages):
                tables = page.extract_tables()
                for t_idx, table in enumerate(tables):
                    if not table:
                        continue

                    # Treat first row as header if it has no matches
                    header = table[0]
                    header_clean = [str(c or "").strip() for c in header]
                    matched_rows = []

                    for row in table[1:]:
                        row_text = " ".join(str(c or "") for c in row)
                        if any(matches(row_text, term) for term in terms):
                            matched_rows.append(row)

                    if matched_rows:
                        table_hits += 1
                        total_hits += len(matched_rows)
                        lines_out.append(
                            f"\n  📌 Page {page_num + 1}, Table {t_idx + 1}:"
                        )
                        # Print header
                        lines_out.append(
                            "  " + " | ".join(f"{h[:18]:<18}" for h in header_clean)
                        )
                        lines_out.append("  " + "-" * min(80, len(header_clean) * 20))
                        # Print matching rows
                        for row in matched_rows:
                            clean = [str(c or "").strip() for c in row]
                            row_str = " | ".join(f"{v[:18]:<18}" for v in clean)
                            # Highlight matched terms
                            for term in terms:
                                row_str = highlight(row_str, term)
                            lines_out.append(f"  {row_str}")

        if table_hits == 0:
            lines_out.append("  — no table matches found")

    except Exception as e:
        return f"PDF search error: {e}"

    lines_out.append(f"\n📋 Total hits: {total_hits}")
    return "\n".join(lines_out)

def tool_get_weather(city: str, forecast: bool = False) -> str:
    if not OPENWEATHER_API_KEY:
        return "OpenWeatherMap not configured. Set OPENWEATHER_API_KEY in .env"
    import requests

    try:
        # Current weather
        resp = requests.get(
            "https://api.openweathermap.org/data/2.5/weather",
            params={"q": city, "appid": OPENWEATHER_API_KEY, "units": "metric"},
            timeout=10,
        )
        if resp.status_code == 404:
            return f"City '{city}' not found."
        if resp.status_code != 200:
            return f"Weather API error {resp.status_code}"

        d = resp.json()
        name     = d["name"]
        country  = d["sys"]["country"]
        temp     = d["main"]["temp"]
        feels    = d["main"]["feels_like"]
        humidity = d["main"]["humidity"]
        desc     = d["weather"][0]["description"].capitalize()
        wind     = d["wind"]["speed"]

        lines = [
            f"🌍 {name}, {country}",
            f"🌡 {temp:.1f}°C (feels like {feels:.1f}°C)",
            f"☁️ {desc}",
            f"💧 Humidity: {humidity}%  💨 Wind: {wind} m/s",
        ]

        if forecast:
            resp2 = requests.get(
                "https://api.openweathermap.org/data/2.5/forecast",
                params={"q": city, "appid": OPENWEATHER_API_KEY, "units": "metric", "cnt": 40},
                timeout=10,
            )
            if resp2.status_code == 200:
                lines.append("\n📅 5-day forecast:")
                seen_days = set()
                for item in resp2.json()["list"]:
                    day = item["dt_txt"][:10]
                    if day in seen_days:
                        continue
                    seen_days.add(day)
                    t     = item["main"]["temp"]
                    desc2 = item["weather"][0]["description"].capitalize()
                    lines.append(f"  {day}: {t:.1f}°C — {desc2}")

        return "\n".join(lines)

    except Exception as e:
        return f"Weather error: {e}"

def tool_get_directions(
    origin: str,
    destination: str,
    mode: str = "transit",
    departure_now: bool = True,
) -> str:
    if not GOOGLE_MAPS_API_KEY:
        return "Google Maps not configured. Set GOOGLE_MAPS_API_KEY in .env"
    import requests
    import time

    try:
        params = {
            "origin":      origin,
            "destination": destination,
            "mode":        mode,
            "key":         GOOGLE_MAPS_API_KEY,
        }
        if departure_now:
            params["departure_time"] = "now"

        resp = requests.get(
            "https://maps.googleapis.com/maps/api/directions/json",
            params=params,
            timeout=10,
        )
        data = resp.json()

        if data["status"] == "NOT_FOUND":
            return f"Could not find route from '{origin}' to '{destination}'."
        if data["status"] == "ZERO_RESULTS":
            return f"No {mode} route found between those locations."
        if data["status"] != "OK":
            return f"Google Maps error: {data['status']}"

        leg = data["routes"][0]["legs"][0]
        duration     = leg["duration"]["text"]
        distance     = leg["distance"]["text"]
        start        = leg["start_address"]
        end          = leg["end_address"]

        # Live traffic duration (driving only)
        duration_traffic = leg.get("duration_in_traffic", {}).get("text")

        lines = [
            f"🗺️ {start} → {end}",
            f"🚩 Mode: {mode}",
            f"📏 Distance: {distance}",
            f"⏱ Duration: {duration}",
        ]
        if duration_traffic:
            lines.append(f"🚦 With live traffic: {duration_traffic}")

        # Transit: list the steps (line names, stops)
        if mode == "transit":
            lines.append("\n🚇 Steps:")
            for step in leg["steps"]:
                travel_mode = step["travel_mode"]
                if travel_mode == "TRANSIT":
                    t         = step["transit_details"]
                    line_name = t["line"].get("short_name") or t["line"].get("name", "?")
                    dep       = t["departure_stop"]["name"]
                    arr       = t["arrival_stop"]["name"]
                    num_stops = t["num_stops"]
                    vehicle   = t["line"]["vehicle"]["type"].capitalize()
                    lines.append(f"  🚉 {vehicle} {line_name}: {dep} → {arr} ({num_stops} stops)")
                elif travel_mode == "WALKING":
                    walk_dur  = step["duration"]["text"]
                    walk_dist = step["distance"]["text"]
                    lines.append(f"  🚶 Walk {walk_dist} ({walk_dur})")

        return "\n".join(lines)

    except Exception as e:
        return f"Directions error: {e}"

def tool_scan_network(subnet: str = None) -> str:
    target = subnet or HOME_SUBNET
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sn --host-timeout 10s")
        hosts = nm.all_hosts()
        if not hosts:
            return f"No devices found on {target}."
        lines = [f"Devices on {target} ({len(hosts)} found):\n"]
        for host in sorted(hosts):
            info = nm[host]
            hostname = info.hostname() or "—"
            state = info.state()
            mac = info.get("addresses", {}).get("mac", "—")
            vendor = ""
            if mac != "—":
                vendor = info.get("vendor", {}).get(mac, "")
            vendor_str = f" ({vendor})" if vendor else ""
            lines.append(f"  {host:<16} {hostname:<24} {mac}{vendor_str}")
        return "\n".join(lines)
    except Exception as e:
        return f"Scan error: {e}"

def tool_breach_search(
    term: str,
    fields: list[str],
    wildcard: bool = False,
    case_sensitive: bool = False,
    minecraft_only: bool = False,
) -> str:
    import requests

    payload = {
        "term": term,
        "fields": fields,
        "wildcard": wildcard,
        "case_sensitive": case_sensitive,
    }
    if minecraft_only:
        payload["categories"] = ["minecraft"]

    try:
        resp = requests.post(
            "https://breach.vip/api/search",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=15,
        )

        body = resp.json()

        if resp.status_code == 429:
            return "⚠️ breach.vip rate limit hit (15 req/min). Try again in a minute."
        if resp.status_code == 400:
            return f"Bad request: {body.get('error', 'unknown error')}"
        if resp.status_code != 200:
            return f"breach.vip error {resp.status_code}: {body.get('error', resp.text[:200])}"

        results = body["results"]
        if not results:
            return f"No breached records found for '{term}' in fields: {', '.join(fields)}."

        lines = [f"Found {len(results)} record(s) for '{term}':\n"]
        for r in results[:10]:
            source = r.pop("source", "?")
            cats = r.pop("categories", "")
            if isinstance(cats, list):
                cats = ", ".join(cats)
            fields_str = " | ".join(f"{k}: {v}" for k, v in r.items() if v)
            lines.append(f"  [{source}] {fields_str}  (categories: {cats})")
        if len(results) > 10:
            lines.append(f"  … and {len(results) - 10} more results.")

        return "\n".join(lines)

    except requests.Timeout:
        return "breach.vip request timed out."
    except Exception as e:
        return f"breach.vip error: {e}"

def tool_generate_usernames(first_name: str, last_name: str) -> list[str]:
    f  = first_name.lower().strip()
    l  = last_name.lower().strip()

    return [
        f"{f}{l}",          # johndoe
        f"{f}.{l}",         # john.doe
        f"{f}_{l}",         # john_doe
        f"{f[0]}{l}",       # jdoe
        f"{l[0]}{f}",       # djohn
        f"{l[0]}.{f}",      # d.john
        f"{f[0]}.{l}",      # j.doe
        f"{l}{f}",          # doejohn
        f"{l}{f[0]}",       # doej
        f"{l}.{f}",         # doe.john
        f"{f}{l[0]}",       # johnd
        f"{f[0]}_{l}",      # j_doe
    ]

def tool_username_hunt(usernames: list[str], timeout: int = 10) -> str:
    all_results = []

    for username in usernames:
        try:
            result = subprocess.run(
                [
                    "sherlock", username,
                    "--print-found",
                    "--no-color",
                    "--timeout", str(timeout),
                    "--output", "/dev/null",  # don't write files
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            found = [
                line.strip()
                for line in result.stdout.splitlines()
                if line.startswith("[+]")
            ]
            if found:
                all_results.append(f"👤 {username} ({len(found)} found):")
                all_results.extend(f"  {line}" for line in found)
            else:
                all_results.append(f"👤 {username}: no profiles found")

        except subprocess.TimeoutExpired:
            all_results.append(f"👤 {username}: timed out")
        except FileNotFoundError:
            return "Sherlock not installed. Run: pip install sherlock-project"
        except Exception as e:
            all_results.append(f"👤 {username}: error — {e}")

    return "\n".join(all_results) if all_results else "No results."

    # ── Web search ────────────────────────────────────────────────────────────
    if "web" in sources and BRAVE_API_KEY:
        lines.append("\n━━ 🌐 Web ━━")
        queries = [
            f"{full_name_variants[0]} {context}".strip(),
            f"{full_name_variants[0]} site:linkedin.com",
            f"{full_name_variants[0]} site:github.com",
        ]
        if company:
            queries.append(f"{full_name_variants[0]} {company} email")

        seen_urls = set()
        for query in queries:
            try:
                resp = requests.get(
                    "https://api.search.brave.com/res/v1/web/search",
                    headers={"X-Subscription-Token": BRAVE_API_KEY, "Accept": "application/json"},
                    params={"q": query, "count": 3},
                    timeout=10,
                )
                if resp.status_code == 200:
                    results = resp.json().get("web", {}).get("results", [])
                    for r in results:
                        url = r.get("url", "")
                        if url not in seen_urls:
                            seen_urls.add(url)
                            title   = r.get("title", "")
                            snippet = r.get("description", "")[:100]
                            lines.append(f"  • {title}\n    {url}\n    {snippet}")
            except Exception:
                pass

    # ── Social search ─────────────────────────────────────────────────────────
    if "social" in sources and BRAVE_API_KEY:
        lines.append("\n━━ 📱 Social media ━━")
        social_queries = {
            "LinkedIn":  f"{full_name_variants[0]} {context} site:linkedin.com/in",
            "Twitter/X": f"{full_name_variants[0]} site:x.com OR site:twitter.com",
            "GitHub":    f"{' '.join(usernames[:3])} site:github.com",
            "Instagram": f"{full_name_variants[0]} site:instagram.com",
        }
        for platform, query in social_queries.items():
            try:
                resp = requests.get(
                    "https://api.search.brave.com/res/v1/web/search",
                    headers={"X-Subscription-Token": BRAVE_API_KEY, "Accept": "application/json"},
                    params={"q": query, "count": 2},
                    timeout=10,
                )
                if resp.status_code == 200:
                    results = resp.json().get("web", {}).get("results", [])
                    if results:
                        for r in results[:1]:
                            lines.append(f"  {platform}: {r.get('url', '')}")
                    else:
                        lines.append(f"  {platform}: no results")
            except Exception:
                pass

    lines.append(f"\n📋 Username combinations tried: {', '.join(usernames)}")
    return "\n".join(lines)

def tool_web_search(query: str, count: int = 10) -> str:
    if not BRAVE_API_KEY:
        return "Brave Search not configured. Set BRAVE_API_KEY in .env"
    import requests

    try:
        resp = requests.get(
            "https://api.search.brave.com/res/v1/web/search",
            headers={
                "X-Subscription-Token": BRAVE_API_KEY,
                "Accept": "application/json",
            },
            params={"q": query, "count": min(count, 20)},
            timeout=10,
        )
        if resp.status_code == 429:
            return "Brave Search rate limited. Try again shortly."
        if resp.status_code != 200:
            return f"Brave Search error {resp.status_code}: {resp.text[:200]}"

        data = resp.json()
        web_results = data.get("web", {}).get("results", [])
        if not web_results:
            return f"No results found for: {query}"

        lines = [f"Search results for '{query}':\n"]
        for i, r in enumerate(web_results, 1):
            title = r.get("title", "No title")
            url = r.get("url", "")
            snippet = r.get("description", "").strip()
            lines.append(f"{i}. {title}\n   {url}\n   {snippet}\n")
        return "\n".join(lines)

    except Exception as e:
        return f"Search error: {e}"


def tool_scrape_page(url: str, extract: list[str] = None) -> str:
    import re
    import requests
    from bs4 import BeautifulSoup

    extract_all = not extract
    want = set(extract or ["emails", "phones", "socials", "links", "text"])

    EMAIL_RE  = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    PHONE_RE  = re.compile(r"(?:\+?\d[\d\s\-().]{7,}\d)")
    SOCIAL_RE = re.compile(
        r"https?://(?:www\.)?"
        r"(twitter\.com|x\.com|linkedin\.com|github\.com|instagram\.com|facebook\.com|t\.me)"
        r"/[^\s\"'>]+"
    )

    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Jarvis/1.0)"},
            timeout=12,
        )
        if resp.status_code != 200:
            return f"Failed to fetch {url}: HTTP {resp.status_code}"

        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        raw_text = soup.get_text(separator=" ", strip=True)
        full_html = resp.text
        lines = [f"Scraped: {url}\n"]

        if "emails" in want:
            # check both visible text and raw HTML (mailto: links etc.)
            emails = sorted(set(EMAIL_RE.findall(raw_text)) | set(EMAIL_RE.findall(full_html)))
            # filter out common false positives
            emails = [e for e in emails if not e.endswith((".png", ".jpg", ".css", ".js"))]
            lines.append(f"📧 Emails ({len(emails)}): {', '.join(emails) if emails else 'none found'}")

        if "phones" in want:
            phones = sorted(set(PHONE_RE.findall(raw_text)))[:10]
            lines.append(f"📞 Phones: {', '.join(phones) if phones else 'none found'}")

        if "socials" in want:
            socials = sorted(set(SOCIAL_RE.findall(full_html)))
            # SOCIAL_RE captures the domain group; redo to get full URLs
            socials = sorted(set(re.findall(
                r"https?://(?:www\.)?(?:twitter|x|linkedin|github|instagram|facebook|t)\.(?:com|me)/[^\s\"'>]+",
                full_html
            )))[:15]
            lines.append(f"🔗 Socials: {', '.join(socials) if socials else 'none found'}")

        if "links" in want:
            hrefs = [a.get("href", "") for a in soup.find_all("a", href=True)]
            ext_links = sorted(set(h for h in hrefs if h.startswith("http") and url not in h))[:15]
            lines.append(f"🌐 External links ({len(ext_links)}):\n  " + "\n  ".join(ext_links))

        if "text" in want:
            # condensed: first 800 chars of meaningful text
            condensed = " ".join(raw_text.split())[:800]
            lines.append(f"\n📄 Page text (condensed):\n{condensed}…")

        return "\n".join(lines)

    except Exception as e:
        return f"Scrape error: {e}"
