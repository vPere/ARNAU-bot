import discord
from config import DISCORD_TOKEN, DISCORD_ALLOWED_USER_ID
from memory import conversations, process_message

def _chunk_text(text: str, size: int = 1990) -> list[str]:
    if len(text) <= size:
        return [text]
    chunks = []
    while text:
        if len(text) <= size:
            chunks.append(text)
            break
        split_at = text.rfind("\n", 0, size)
        if split_at == -1:
            split_at = size
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks

class ArnauDiscord(discord.Client):
    async def on_ready(self):
        print(f"✅ Discord: Arnau online as {self.user}")

    async def on_message(self, message: discord.Message):
        if message.author == self.user:
            return
        if message.author.id != DISCORD_ALLOWED_USER_ID:
            await message.channel.send("Unauthorized.")
            return
        content = message.content.strip()
        if content.lower() == "!clear":
            conversations.pop(f"dc:{message.author.id}", None)
            await message.channel.send("Conversation history cleared.")
            return
        async with message.channel.typing():
            reply = await process_message(f"dc:{message.author.id}", content)
        for chunk in _chunk_text(reply):
            await message.channel.send(chunk)

async def run():
    intents = discord.Intents.default()
    intents.message_content = True
    await ArnauDiscord(intents=intents).start(DISCORD_TOKEN)