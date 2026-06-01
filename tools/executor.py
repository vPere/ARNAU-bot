from tools.implementations import *

def execute_tool(name: str, inputs: dict) -> str:
    if name == "wake_pc":
        return tool_wake_pc()
    elif name == "list_vms":
        return tool_list_vms()
    elif name == "vm_action":
        return tool_vm_action(inputs["vmid"], inputs["action"])
    elif name == "control_lights":
        return tool_control_lights(
            inputs["action"],
            inputs.get("brightness"),
            inputs.get("color")
        )
    elif name == "shodan_query":
        return tool_shodan_query(inputs["type"], inputs["query"])
    elif name == "scan_network":
        return tool_scan_network(inputs.get("subnet"))
    elif name == "breach_search":
        return tool_breach_search(
            inputs["term"],
            inputs["fields"],
            inputs.get("wildcard", False),
            inputs.get("case_sensitive", False),
            inputs.get("minecraft_only", False),
        )
    elif name == "web_search":
        return tool_web_search(inputs["query"], inputs.get("count", 10))
    elif name == "scrape_page":
        return tool_scrape_page(inputs["url"], inputs.get("extract"))
    elif name == "get_weather":
        return tool_get_weather(inputs["city"], inputs.get("forecast", False))
    elif name == "get_directions":
        return tool_get_directions(
            inputs["origin"],
            inputs["destination"],
            inputs.get("mode", "transit"),
            inputs.get("departure_now", True),
        )
    elif name == "whois_lookup":
        return tool_whois_lookup(inputs["domain"])
    elif name == "dns_lookup":
        return tool_dns_lookup(
            inputs["domain"],
            inputs.get("record_types"),
            inputs.get("subdomains", False),
        )
    elif name == "username_hunt":
        return tool_username_hunt(
            inputs["usernames"],
            inputs.get("timeout", 10)
        )
    elif name == "search_pdf":
        return tool_search_pdf(
            inputs["url"],
            inputs.get("terms"),
            inputs.get("fuzzy", True),
            inputs.get("context_lines", 2),
        )
    return f"Unknown tool: {name}"