import asyncio
from tools.home.implementations import *
from tools.osint.implementations import *

async def execute_tool(name: str, inputs: dict) -> str:
    if name == "wake_pc":
        result = tool_wake_pc()
    elif name == "list_vms":
        result = tool_list_vms()
    elif name == "vm_action":
        result = tool_vm_action(inputs["vmid"], inputs["action"])
    elif name == "control_lights":
        result = tool_control_lights(
            inputs["action"],
            inputs.get("brightness"),
            inputs.get("color")
        )
    elif name == "shodan_query":
        result = tool_shodan_query(inputs["type"], inputs["query"])
    elif name == "censys_query":
        result = tool_censys_query(inputs["type"], inputs["query"])
    elif name == "scan_network":
        result = tool_scan_network(inputs.get("subnet"))
    elif name == "web_search":
        result = tool_web_search(inputs["query"], inputs.get("count", 10))
    elif name == "scrape_page":
        result = tool_scrape_page(inputs["url"], inputs.get("extract"))
    elif name == "get_weather":
        result = tool_get_weather(inputs["city"], inputs.get("forecast", False))
    elif name == "get_directions":
        result = tool_get_directions(
            inputs["origin"],
            inputs["destination"],
            inputs.get("mode", "transit"),
            inputs.get("departure_now", True),
        )
    elif name == "whois_lookup":
        result = tool_whois_lookup(inputs["domain"])
    elif name == "dns_lookup":
        result = tool_dns_lookup(
            inputs["domain"],
            inputs.get("record_types"),
            inputs.get("subdomains", False),
        )
    elif name == "username_hunt":
        result = tool_username_hunt(
            inputs["usernames"],
            inputs.get("timeout", 10)
        )
    elif name == "search_pdf":
        result = tool_search_pdf(
            inputs["url"],
            inputs.get("terms"),
            inputs.get("fuzzy", True),
            inputs.get("context_lines", 2),
        )
    elif name == "scan_host":
        result = tool_scan_host(
            inputs["host"],
            inputs.get("ports"),
            inputs.get("os_detection", True),
            inputs.get("vuln_scan", False),
        )
    elif name == "breach_search":
        result = tool_breach_search(
            inputs["term"],
            inputs["fields"],
            inputs.get("wildcard", False),
            inputs.get("case_sensitive", False),
            inputs.get("minecraft_only", False),
        )
    else:
        return f"Unknown tool: {name}"

    if asyncio.iscoroutine(result):
        result = await result
    return result