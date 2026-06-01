import asyncio
from config import TELEGRAM_TOKEN, DISCORD_TOKEN
from bot.telegram_bot import run as run_telegram
from bot.discord_bot import run as run_discord

async def _main():
    tasks = []
    if TELEGRAM_TOKEN:
        tasks.append(run_telegram())
    if DISCORD_TOKEN:
        tasks.append(run_discord())
    if not tasks:
        raise RuntimeError("No TELEGRAM_TOKEN or DISCORD_TOKEN configured.")
    print("✅ ARNAU is online.")
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass

if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        print("\n🛑 ARNAU shutting down.")