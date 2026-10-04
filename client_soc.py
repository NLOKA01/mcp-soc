#!/usr/bin/env python3
"""
client_soc.py — Client MCP pour le projet SOC augmenté par IA
"""

import asyncio
import json
import traceback

import httpx2
import ollama
from mcp import ClientSession
from mcp.client.sse import sse_client
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel


MCP_URL = "http://192.168.20.10:8000/sse"
OLLAMA_MODEL = "qwen2.5:3b"
MCP_TOKEN = ""  # vide en mode TEST

# OUTILS SENSIBLES (validation humaine obligatoire)
OUTILS_SENSIBLES = {"block_ip_firewall", "isolate_endpoint"}

console = Console()


def mcp_tool_to_ollama(tool) -> dict:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.input_schema or {"type": "object", "properties": {}},
        },
    }


def extraire_texte(result) -> str:
    texte = ""
    for content in result.content:
        if hasattr(content, "text"):
            texte += content.text
    return texte


async def repondre(session: ClientSession, question: str) -> str:
    tools_response = await session.list_tools()
    ollama_tools = [mcp_tool_to_ollama(t) for t in tools_response.tools]
    console.print(f"[dim]→ {len(ollama_tools)} outils chargés[/dim]")

    messages = [{"role": "user", "content": question}]

    while True:
        console.print("\n[cyan] Réflexion du modèle...[/cyan]")

        try:
            response = ollama.chat(
                model=OLLAMA_MODEL,
                messages=messages,
                tools=ollama_tools,
            )
        except Exception as e:
            return f"Erreur Ollama : {e}"

        msg = response["message"]
        tool_calls = msg.get("tool_calls") or []

        if not tool_calls:
            return msg.get("content", "(réponse vide)")

        messages.append({
            "role": "assistant",
            "content": msg.get("content", ""),
            "tool_calls": tool_calls,
        })

        for call in tool_calls:
            fn_name = call["function"]["name"]
            fn_args = call["function"]["arguments"]

            if isinstance(fn_args, str):
                try:
                    fn_args = json.loads(fn_args)
                except json.JSONDecodeError:
                    fn_args = {}

            console.print(f"[yellow]🔧 Appel MCP : {fn_name}({fn_args})[/yellow]")

            # VALIDATION HUMAINE POUR ACTIONS SENSIBLES
            if fn_name in OUTILS_SENSIBLES:
                console.print()
                console.print("[bold red]  ACTION SENSIBLE DÉTECTÉE[/bold red]")
                console.print(f"[red]Outil :[/red] {fn_name}")
                console.print(f"[red]Arguments :[/red] {fn_args}")
                try:
                    reponse_user = console.input(
                        "[bold yellow]Autoriser cette action ? (y/n) > [/bold yellow]"
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    reponse_user = "n"

                if reponse_user != "y":
                    texte = "❌ Action refusée par l'analyste."
                    console.print(f"[red]{texte}[/red]")
                    messages.append({
                        "role": "tool",
                        "tool_name": fn_name,
                        "content": texte,
                    })
                    continue

                console.print("[green]  Action autorisée par l'analyste[/green]")

            try:
                result = await session.call_tool(fn_name, fn_args)
                texte = extraire_texte(result)
                console.print(f"[green] Résultat : {len(texte)} caractères[/green]")
            except Exception as e:
                texte = f"Erreur {fn_name} : {e}"
                console.print(f"[red] {texte}[/red]")

            messages.append({
                "role": "tool",
                "tool_name": fn_name,
                "content": texte,
            })


async def main():
    console.print(Panel.fit(
        "[bold cyan]Client MCP SOC — Projet Cybersécurité IA[/bold cyan]\n"
        f"Serveur MCP : {MCP_URL}\n"
        f"Modèle Ollama : {OLLAMA_MODEL}\n"
        f"Auth : {'JWT' if MCP_TOKEN else 'Mode TEST (sans JWT)'}"
    ))

    http_headers = {}
    if MCP_TOKEN:
        http_headers["Authorization"] = f"Bearer {MCP_TOKEN}"

    try:
        async with sse_client(MCP_URL, headers=http_headers) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                console.print("[green]✓ Connecté au serveur MCP[/green]")

                while True:
                    try:
                        question = console.input("\n[bold cyan]Question > [/bold cyan]").strip()
                    except (EOFError, KeyboardInterrupt):
                        break

                    if not question:
                        continue
                    if question.lower() in ("exit", "quit", "/q"):
                        break

                    try:
                        answer = await repondre(session, question)
                        console.print()
                        console.print(Panel(
                            Markdown(answer),
                            title="📝 Réponse finale",
                            border_style="green",
                        ))
                    except Exception as e:
                        console.print(f"[red]Erreur : {e}[/red]")
                        traceback.print_exc()
    except Exception as e:
        console.print(f"[red]Impossible de se connecter : {e}[/red]")
        traceback.print_exc()

    console.print("\n[dim]Session terminée.[/dim]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
