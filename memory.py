from config import bedrock, BEDROCK_MODEL
from tools.osint.definitions import TOOLS as OSINT_TOOLS
from tools.home.definitions import TOOLS as HOME_TOOLS
from tools.executor import execute_tool
from system_prompt import SYSTEM_PROMPT

TOOLS = OSINT_TOOLS + HOME_TOOLS
conversations: dict[str, list] = {}

async def process_message(user_id: str, text: str) -> str:
    history = conversations.setdefault(user_id, [])
    history.append({"role": "user", "content": text})
    messages = history[-20:]

    while True:
        response = bedrock.messages.create(
            model=BEDROCK_MODEL,
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )
        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = execute_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })
            messages.append({"role": "user", "content": tool_results})
        else:
            reply = "".join(b.text for b in response.content if hasattr(b, "text"))
            history.append({"role": "assistant", "content": reply})
            return reply