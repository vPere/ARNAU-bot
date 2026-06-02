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
    }
]