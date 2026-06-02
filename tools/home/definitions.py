from config import HOME_SUBNET

TOOLS = [
    {
        "name": "wake_pc",
        "description": "Wake up the user's PC via Wake-on-LAN magic packet.",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "list_vms",
        "description": "List all VMs on the Proxmox server with their current status.",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "vm_action",
        "description": "Perform an action (start/stop/reboot/status) on a Proxmox VM.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vmid":   {"type": "integer", "description": "The VM ID number"},
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "reboot", "status"],
                    "description": "Action to perform on the VM"
                }
            },
            "required": ["vmid", "action"]
        }
    },
    {
        "name": "scan_network",
        "description": (
            "Scan the local home network and list all connected devices with their "
            "IP address, MAC address, and hostname if available."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "subnet": {
                    "type": "string",
                    "description": f"Subnet to scan in CIDR notation (default: {HOME_SUBNET})"
                }
            },
            "required": []
        }
    },
    {
    "name": "get_weather",
    "description": "Get current weather and 5-day forecast for any city.",
    "input_schema": {
        "type": "object",
        "properties": {
            "city": {
                "type": "string",
                "description": "City name, e.g. 'London' or 'London,UK'"
            },
            "forecast": {
                "type": "boolean",
                "description": "Include 5-day forecast (default: false, current only)"
            }
        },
        "required": ["city"]
        }
    },
    {
    "name": "get_directions",
    "description": (
        "Get travel time and directions between two places using Google Maps. "
        "Supports driving, walking, bicycling, and transit (public transport). "
        "Can factor in live traffic and departure time."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "origin": {"type": "string", "description": "Start address or place name"},
            "destination": {"type": "string", "description": "End address or place name"},
            "mode": {
                "type": "string",
                "enum": ["driving", "walking", "bicycling", "transit"],
                "description": "Travel mode (default: transit)"
            },
            "departure_now": {
                "type": "boolean",
                "description": "Use current time as departure to get live traffic/transit (default: true)"
            }
        },
        "required": ["origin", "destination"]
        }
    },
    {
    "name": "scan_host",
    "description": (
        "Deep scan a specific host: open ports with service/version detection, "
        "OS fingerprinting, and optional vulnerability detection via nmap scripts. "
        "Use this on a specific IP or hostname, not a whole subnet."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "IP address or hostname to scan"
            },
            "ports": {
                "type": "string",
                "description": "Port range to scan (default: top 1000). Examples: '22,80,443', '1-65535', '1-1024'"
            },
            "os_detection": {
                "type": "boolean",
                "description": "Attempt OS fingerprinting (requires root, default: true)"
            },
            "vuln_scan": {
                "type": "boolean",
                "description": "Run nmap vuln scripts to detect known CVEs (slower, default: false)"
            }
        },
        "required": ["host"]
    }
 },
]