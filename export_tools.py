import asyncio
import json
from server import mcp


async def exporter():
    tools = await mcp.list_tools()
    result = []
    for t in tools:
        result.append({
            "name": t.name,
            "description": (t.description or "").strip(),
            "input_schema": t.parameters,
        })

    with open("tools.json", "w", encoding="utf-8") as f:
        json.dump({"tools": result}, f, indent=2, ensure_ascii=False)

    print(f"OK - {len(result)} outils exportes dans tools.json")
    for t in result:
        print(f"  - {t['name']}")


if __name__ == "__main__":
    asyncio.run(exporter())
