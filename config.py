import os
from dotenv import load_dotenv
load_dotenv()

TELEGRAM_TOKEN          = os.environ["TELEGRAM_TOKEN"]
ALLOWED_USER_ID         = int(os.environ["ALLOWED_USER_ID"])
PC_MAC                  = os.environ["PC_MAC"]
PROXMOX_HOST            = os.environ.get("PROXMOX_HOST")
PROXMOX_PORT            = int(os.environ.get("PROXMOX_PORT", "8006"))
PROXMOX_USER            = os.environ.get("PROXMOX_USER", "root@pam")
PROXMOX_PASSWORD        = os.environ["PROXMOX_PASSWORD"]
PROXMOX_NODE            = os.environ.get("PROXMOX_NODE", "pve")
LIGHT_IP                = os.environ.get("LIGHT_IP", "")
LIGHT_TOKEN             = os.environ.get("LIGHT_TOKEN", "")
SHODAN_API_KEY          = os.environ.get("SHODAN_API_KEY", "")
CENSYS_API_ID           = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET       = os.environ.get("CENSYS_API_SECRET", "")
BRAVE_API_KEY           = os.environ.get("BRAVE_API_KEY", "")
OPENWEATHER_API_KEY     = os.environ.get("OPENWEATHER_API_KEY", "")
GOOGLE_MAPS_API_KEY     = os.environ.get("GOOGLE_MAPS_API_KEY", "")
DISCORD_TOKEN           = os.environ.get("DISCORD_TOKEN", "")
DISCORD_ALLOWED_USER_ID = int(os.environ.get("DISCORD_ALLOWED_USER_ID", "0"))
HOME_SUBNET             = os.environ.get("HOME_SUBNET", "192.168.1.0/24")
BEDROCK_MODEL           = os.environ.get("BEDROCK_MODEL", "us.anthropic.claude-3-5-sonnet-20241022-v2:0")

import anthropic
bedrock = anthropic.AnthropicBedrock(
    aws_access_key=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    aws_region=os.environ.get("AWS_REGION", "us-east-1"),
)