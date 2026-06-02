from config import HOME_SUBNET

TOOLS = [
    {
        "name": "shodan_query",
        "description": (
            "Query Shodan. Use type='search' to search for devices/services on the internet, "
            "or type='host' to look up details about a specific IP address."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["search", "host"],
                    "description": "'search' for a keyword/filter query, 'host' to look up an IP"
                },
                "query": {
                    "type": "string",
                    "description": "Search query string or IP address"
                }
            },
            "required": ["type", "query"]
        }
    },
    {
    "name": "search_pdf",
    "description": (
        "Download a PDF and search its text and tables for specific terms. "
        "Returns matching rows from tables and surrounding context from text. "
        "Ideal for finding a person's name, ID, email, or any value inside a document."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Direct URL to the PDF"
            },
            "terms": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Terms to search for, e.g. ['John Doe', 'john.doe@company.com']"
            },
            "fuzzy": {
                "type": "boolean",
                "description": "Also match partial/case-insensitive occurrences (default: true)"
            },
            "context_lines": {
                "type": "integer",
                "description": "Lines of surrounding text to return around each match (default: 2)"
            }
        },
        "required": ["url", "terms"]
    }
    },
    {
    "name": "whois_lookup",
    "description": (
        "Look up WHOIS data for a domain: owner/registrant, registrar, "
        "creation date, expiry date, nameservers, and status."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain to look up, e.g. 'example.com'"}
        },
        "required": ["domain"]
    }
    },
    {
    "name": "dns_lookup",
    "description": "Query DNS records for a domain (A, MX, TXT, NS, CNAME) and enumerate subdomains via certificate transparency logs (crt.sh).",
    "input_schema": {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain to query"},
            "record_types": {
                "type": "array",
                "items": {"type": "string", "enum": ["A", "MX", "TXT", "NS", "CNAME"]},
                "description": "Record types to fetch. Omit for all."
            },
            "subdomains": {
                "type": "boolean",
                "description": "Enumerate subdomains via crt.sh certificate transparency logs (default: false)"
            }
        },
        "required": ["domain"]
        }
    },
    {
    "name": "breach_search",
    "description": (
        "Search the breach.vip database for leaked/compromised records across 10B+ entries. "
        "Supports wildcards: '*' matches zero or more chars, '?' matches exactly one (terms cannot START with a wildcard). "
        "Rate limit: 15 requests/minute."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "term": {
                "type": "string",
                "description": "Search term (1–100 chars). Wildcards supported if wildcard=true, e.g. 'user@*.com'"
            },
            "fields": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["domain", "steamid", "phone", "name", "email",
                             "username", "password", "ip", "discordid", "uuid"]
                },
                "description": "Which field(s) to search. Required. 1–10 fields."
            },
            "wildcard": {
                "type": "boolean",
                "description": "Enable wildcard operators (* and ?) in the term. Default: false."
            },
            "case_sensitive": {
                "type": "boolean",
                "description": "Case-sensitive matching. Default: false."
            },
            "minecraft_only": {
                "type": "boolean",
                "description": "Restrict results to Minecraft-related breaches only. Default: false."
            }
        },
        "required": ["term", "fields"]
    }
},
{
    "name": "username_hunt",
    "description": (
        "Use Sherlock to check a username across 300+ social media platforms "
        "simultaneously. Returns all sites where the username was found. "
        "Use this when searching for a person to find their social media presence."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "usernames": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of usernames to check (e.g. ['johndoe', 'john.doe', 'jdoe'])"
            },
            "timeout": {
                "type": "integer",
                "description": "Seconds to wait per site (default: 10)"
            }
        },
        "required": ["usernames"]
    }
},
{
    "name": "web_search",
    "description": (
        "Search the web using Brave Search. Great for finding public info about "
        "businesses, people, or any topic. Supports Google-style dork operators: "
        "site:, filetype:, inurl:, intitle:, etc. Returns titles, URLs, and snippets. "
        "Use this before scrape_page to find relevant URLs to dig into."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "Search query. Dork examples: "
                    "'site:example.com email contact', "
                    "'\"John Doe\" linkedin', "
                    "'filetype:pdf site:company.com report'"
                )
            },
            "count": {
                "type": "integer",
                "description": "Number of results to return (1–20, default: 10)"
            }
        },
        "required": ["query"]
    }
},
{
    "name": "scrape_page",
    "description": (
        "Fetch a URL and extract useful OSINT data: email addresses, phone numbers, "
        "social media links, and a summary of the page text. "
        "Use this after web_search to dig into specific pages."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Full URL to fetch and scrape"
            },
            "extract": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["emails", "phones", "socials", "links", "text"]
                },
                "description": "What to extract. Omit for all. 'text' returns a condensed page summary."
            }
        },
        "required": ["url"]
    }
},
]