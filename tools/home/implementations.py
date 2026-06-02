import nmap
from proxmoxer import ProxmoxAPI
from wakeonlan import send_magic_packet
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

def tool_scan_host(
    host: str,
    ports: str = None,
    os_detection: bool = True,
    vuln_scan: bool = False,
) -> str:
    try:
        nm = nmap.PortScanner()

        # Build arguments
        args = "-sV"                          # service/version detection
        if os_detection:
            args += " -O --osscan-guess"      # OS fingerprint
        if vuln_scan:
            args += " --script vuln"          # CVE scripts (slow)
        if ports:
            args += f" -p {ports}"

        nm.scan(hosts=host, arguments=args, sudo=os_detection)

        if host not in nm.all_hosts():
            return f"Host {host} is down or unreachable."

        info   = nm[host]
        state  = info.state()
        lines  = [f"🖥️  Host: {host} [{state}]"]

        # ── OS detection ──────────────────────────────────────────────────
        if os_detection and "osmatch" in info and info["osmatch"]:
            best = info["osmatch"][0]
            lines.append(
                f"🔍 OS: {best['name']} "
                f"(accuracy: {best['accuracy']}%)"
            )
            if len(info["osmatch"]) > 1:
                others = ", ".join(
                    f"{m['name']} ({m['accuracy']}%)"
                    for m in info["osmatch"][1:3]
                )
                lines.append(f"   Also possible: {others}")
        elif os_detection:
            lines.append("🔍 OS: could not determine")

        # ── Open ports + services ─────────────────────────────────────────
        lines.append("\n📡 Open ports:")
        found_ports = False
        for proto in info.all_protocols():
            for port in sorted(info[proto].keys()):
                p = info[proto][port]
                if p["state"] != "open":
                    continue
                found_ports = True
                service = p.get("name", "?")
                product = p.get("product", "")
                version = p.get("version", "")
                extrainfo = p.get("extrainfo", "")
                detail = " ".join(filter(None, [product, version, extrainfo]))
                lines.append(
                    f"  {port}/{proto:<4} {service:<12} {detail}"
                )

                # ── Vuln results per port ──────────────────────────────
                if vuln_scan and "script" in p:
                    for script_name, output in p["script"].items():
                        # Only show if it looks like a real finding
                        if any(kw in output.lower() for kw in
                               ["vulnerable", "cve", "risk", "exploit"]):
                            # Trim long output
                            trimmed = output.strip()[:300]
                            lines.append(f"    ⚠️  [{script_name}]")
                            for l in trimmed.splitlines()[:6]:
                                lines.append(f"       {l.strip()}")

        if not found_ports:
            lines.append("  No open ports found in scanned range.")

        # ── Host-level vuln scripts (not port-specific) ───────────────────
        if vuln_scan and "hostscript" in info:
            lines.append("\n⚠️  Host-level findings:")
            for script in info["hostscript"]:
                output = script.get("output", "").strip()[:300]
                if any(kw in output.lower() for kw in
                       ["vulnerable", "cve", "risk", "exploit"]):
                    lines.append(f"  [{script['id']}]")
                    for l in output.splitlines()[:6]:
                        lines.append(f"    {l.strip()}")

        return "\n".join(lines)

    except nmap.PortScannerError as e:
        return f"nmap error (are you root?): {e}"
    except Exception as e:
        return f"Scan error: {e}"
