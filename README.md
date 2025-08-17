# mcp-server-ollama-nmap

Awesome—let’s wire up a tiny FastMCP stack that lets **Qwen3 (via local Ollama)** decide which **Nmap** scan to run, and a **FastMCP server** actually execute the scan. We’ll use **uv** for the Python project on **Windows 11 Terminal** (PowerShell).

**My assumptions (confidence ≈ 0.85):**

* You have admin rights (needed for some Nmap scans on Windows).
* You’re fine using Winget to install Nmap; otherwise grab the installer from nmap.org.
* You want a minimal, readable reference you can extend.

---

# 1) Prereqs (PowerShell)

```powershell
# 1) Install uv (official Astral installer)
powershell -ExecutionPolicy Bypass -c "irm https://astral.sh/uv/install.ps1 | iex"

# 2) Install Nmap (Winget package)
winget install -e --id Insecure.Nmap

# 3) Install Ollama for Windows (official GUI/CLI)
# (Download & install from https://ollama.com — then:)
ollama serve  # leave running in background
ollama pull qwen3:latest
```

**Why these steps?** Astral’s docs show the PowerShell one-liner for uv install, and Winget’s Nmap ID is `Insecure.Nmap`. Qwen3 has an official Ollama library page (and supports “tools”). ([Astral Docs][1], [Winget.run][2], [Ollama][3])

---

# 2) Project skeleton (uv)

```powershell
# New project
uv init fastmcp-nmap
cd fastmcp-nmap

# Add deps:
# - "mcp[cli]" = official MCP SDK (+dev CLI)
# - fastmcp = ergonomic server/client layer
# - requests = talk to Ollama HTTP API
uv add "mcp[cli]" fastmcp requests
```

FastMCP 2.0 is the high-level wrapper; official SDK provides the client plumbing and `mcp` CLI. ([GitHub][4], [FastMCP][5])

---

# 3) FastMCP **server**: `server.py`

This exposes one tool `nmap_scan()` that supports common profiles (`tcp_connect`, `tcp_syn`, `udp`, `version`, `vuln`, `top1000`, `full_tcp`). It validates inputs and returns stdout.

> Save as `server.py` in the project root.

```python
from __future__ import annotations
import subprocess, shutil, sys
from pathlib import Path
from typing import Literal, Optional, Dict, Any, List

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.session import ServerSession

mcp = FastMCP("nmap-server")

ScanType = Literal[
    "tcp_connect",  # -sT
    "tcp_syn",      # -sS (needs admin + npcap)
    "udp",          # -sU
    "version",      # -sV
    "vuln",         # --script vuln
    "top1000",      # default top-1000 TCP
    "full_tcp"      # -p0-65535
]

def _which_or_raise(exe: str) -> str:
    p = shutil.which(exe)
    if not p:
        raise RuntimeError(f"{exe} not found in PATH. Install it and reopen your terminal.")
    return p

def _common_args(scan_type: ScanType) -> List[str]:
    # Reasonable defaults for Windows; tweak as you like
    if scan_type == "tcp_connect":
        return ["-sT", "-Pn", "-n"]
    if scan_type == "tcp_syn":
        return ["-sS", "-Pn", "-n"]
    if scan_type == "udp":
        return ["-sU", "-Pn", "-n", "--top-ports", "100"]
    if scan_type == "version":
        return ["-sS", "-sV", "-Pn", "-n", "--version-light"]
    if scan_type == "vuln":
        return ["-sS", "-Pn", "-n", "--script", "vuln"]
    if scan_type == "top1000":
        return ["-sS", "-Pn", "-n"]
    if scan_type == "full_tcp":
        return ["-sS", "-Pn", "-n", "-p", "0-65535"]
    return []

def _ports_arg(ports: Optional[str]) -> List[str]:
    if not ports:
        return []
    # Allow "80,443", "1-1024", etc.
    return ["-p", ports]

@mcp.tool()
def list_scan_profiles() -> Dict[str, Any]:
    """List supported scan profiles and what they do."""
    return {
        "profiles": {
            "tcp_connect": "TCP connect scan (-sT)",
            "tcp_syn":     "TCP SYN scan (-sS, admin + npcap)",
            "udp":         "Top 100 UDP ports (-sU --top-ports 100)",
            "version":     "TCP SYN + version detection (-sS -sV)",
            "vuln":        "Vuln script category (--script vuln)",
            "top1000":     "Default top 1000 TCP ports",
            "full_tcp":    "All TCP ports (-p0-65535)"
        }
    }

@mcp.tool()
def nmap_scan(
    target: str,
    scan_type: ScanType = "top1000",
    ports: Optional[str] = None,
    os_detect: bool = False,
    extra: Optional[str] = None,
    ctx: Context[ServerSession, None] = None
) -> Dict[str, Any]:
    """
    Run an Nmap scan.

    Args:
        target: IP or CIDR or hostname (e.g., "192.168.1.10" or "scanme.nmap.org").
        scan_type: One of tcp_connect, tcp_syn, udp, version, vuln, top1000, full_tcp.
        ports: Optional port list or range, e.g., "80,443" or "1-1024".
        os_detect: Whether to attempt OS detection (-O). Requires admin and good conditions.
        extra: Extra raw args string (advanced).
    Returns:
        Dict with command, stdout, stderr, and exit_code.
    """
    nmap = _which_or_raise("nmap")

    args = [nmap]
    args += _common_args(scan_type)
    args += _ports_arg(ports)

    if os_detect:
        args.append("-O")

    if extra:
        # Simple split; you can harden this if you expect quotes, etc.
        args += extra.split()

    # Avoid ambiguous targets / accidental wide scans
    safe_target = target.strip()
    if not safe_target:
        raise ValueError("Empty target.")
    args += [safe_target]

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            shell=False
        )
        return {
            "command": " ".join(args),
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr
        }
    except FileNotFoundError:
        raise RuntimeError("Nmap not found. Ensure it's installed and in PATH.")
    except Exception as e:
        return {
            "command": " ".join(args),
            "exit_code": -1,
            "stdout": "",
            "stderr": f"{type(e).__name__}: {e}"
        }

if __name__ == "__main__":
    # stdio transport by default when run via `uv run mcp dev server.py`
    mcp.run()
```

**Notes:**

* `-sS` requires admin and npcap on Windows; if that fails, use `tcp_connect` (`-sT`). ([Nmap][6])

---

# 4) **Client** that uses **Ollama (Qwen3)** tool-calling to drive the MCP tool: `client.py`

This script:

1. Spawns the server via stdio (official MCP client codepath).
2. Calls Ollama `/api/chat` with a **tool** schema describing `nmap_scan`.
3. When Qwen3 returns a tool call, it’s executed against the MCP server, and the result is fed back to the model.
4. Prints the final answer.

> Save as `client.py`.

```python
from __future__ import annotations
import asyncio, os, json, requests
from typing import Dict, Any
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.shared.context import RequestContext

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:latest")

# Define tool schema for Qwen3 (aligned with server.nmap_scan signature)
NMAP_TOOL = {
    "type": "function",
    "function": {
        "name": "nmap_scan",
        "description": "Run an Nmap scan against a target.",
        "parameters": {
            "type": "object",
            "properties": {
                "target":    {"type": "string", "description": "Target host/IP/CIDR"},
                "scan_type": {"type": "string", "enum": [
                    "tcp_connect","tcp_syn","udp","version","vuln","top1000","full_tcp"
                ]},
                "ports":     {"type": "string", "description": "e.g., 80,443 or 1-1024", "nullable": True},
                "os_detect": {"type": "boolean", "default": False},
                "extra":     {"type": "string", "description": "additional Nmap flags", "nullable": True}
            },
            "required": ["target"]
        }
    }
}

SYSTEM_PROMPT = """You are a penetration testing assistant.
- Choose and call the tool `nmap_scan` to run real scans.
- Prefer minimal, targeted scans first (top1000) and escalate only when asked.
- Always include the command that was executed and summarize key findings."""

def ollama_chat(messages: list[dict], tools: list[dict]) -> Dict[str, Any]:
    resp = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": MODEL,
            "messages": messages,
            "tools": tools,
            "stream": False
        },
        timeout=600
    )
    resp.raise_for_status()
    return resp.json()

async def main():
    # Start/attach to our FastMCP server via stdio
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "server.py"],  # run our local server
        env=os.environ.copy()
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Chat loop: one-shot demonstration; extend as you like
            user_query = input("What do you want to scan? ")
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_query}
            ]

            # First roundtrip
            result = ollama_chat(messages, [NMAP_TOOL])
            messages.append({"role": "assistant", "content": result["message"]["content"]})

            # Handle tool calls (Qwen3 may produce multiple)
            tool_calls = result["message"].get("tool_calls", []) or []
            for call in tool_calls:
                if call.get("function", {}).get("name") == "nmap_scan":
                    args = call["function"].get("arguments") or {}
                    # Execute via MCP
                    mcp_result = await session.call_tool("nmap_scan", arguments=args)
                    # Feed back into the model as a tool result
                    tool_content = {
                        "role": "tool",
                        "name": "nmap_scan",
                        "content": json.dumps(mcp_result.structuredContent or {})
                    }
                    messages.append(tool_content)

            # Ask Qwen3 to produce a final summary given tool outputs
            final = ollama_chat(messages + [{"role": "user", "content": "Summarize results succinctly."}], [NMAP_TOOL])
            print("\n=== Assistant ===\n")
            print(final["message"]["content"])

if __name__ == "__main__":
    asyncio.run(main())
```

**Why this shape?**

* The **official MCP Python SDK** demonstrates using `ClientSession` over **stdio** and invoking `session.call_tool`. We’re following that pattern.
* **Qwen3** supports **tools** in Ollama; we advertise a function schema and round-trip tool results back. ([GitHub][4], [Ollama][3])

---

# 5) Run it

```powershell
# From project root
# (1) Helpful: verify the server with the MCP dev inspector
uv run mcp dev server.py

# (2) Then run the client (in a new terminal)
uv run python client.py
# Example prompt:
# > Scan scanme.nmap.org with a quick TCP top1000.
```

---

# 6) Quick verification checklist

* **Server starts**: `uv run mcp dev server.py` shows tools `nmap_scan`, `list_scan_profiles`. (confidence ≈ 0.9) ([GitHub][4])
* **Ollama**: `ollama list` shows `qwen3:latest`; `ollama serve` is running. (≈ 0.9) ([Ollama][3])
* **Nmap**: `nmap -V` works; if `-sS` fails on Windows, try `tcp_connect`. (≈ 0.8) ([Nmap][6])
* **Client flow**: Model emits a `tool_call` for `nmap_scan`; the client executes and feeds back the JSON; model summarizes. (≈ 0.75) ([GitHub][4])

---

# 7) Notes & extensions

* **Privileges**: For `-sS` and `-O` on Windows you typically need admin and **Npcap** in WinPcap compatible mode. If you see permission errors, switch to `tcp_connect` or run elevated. (≈ 0.85) ([Nmap][6])
* **Model variants**: If `qwen3:latest` is heavy, try smaller tags like `qwen3:8b` or `qwen3:14b`. Check tags on the Ollama page. (≈ 0.9) ([Ollama][7])
* **uv tips**: You can also install uv via Winget (`winget install --id=astral-sh.uv -e`) or upgrade with `uv self update`. (≈ 0.95) ([Astral Docs][1])
* **Hardening**: Add allowlists, CIDR guards, output parsers (`-oX` XML), and progress streaming via FastMCP contexts for long scans.

---

## How sure am I?

* Overall setup working end-to-end: **\~80%**.
* Exact `client.py` tool-calling shape with Qwen3 via Ollama: **\~70%** (Ollama’s tool-calling is consistent, but minor response shape diffs can happen across versions).
* FastMCP + MCP client usage: **\~90%** (based on current docs and examples). ([GitHub][4], [FastMCP][5])

If you want, I can add a **“scan profile” prompt** that forces the model to pick profiles deterministically, plus a **CSV/JSON reporter** for results.

[1]: https://docs.astral.sh/uv/getting-started/installation/ "Installation | uv"
[2]: https://winget.run/pkg/Insecure/Nmap?utm_source=chatgpt.com "Download and install Nmap with winget"
[3]: https://ollama.com/library/qwen3?utm_source=chatgpt.com "qwen3"
[4]: https://github.com/modelcontextprotocol/python-sdk "GitHub - modelcontextprotocol/python-sdk: The official Python SDK for Model Context Protocol servers and clients"
[5]: https://gofastmcp.com/getting-started/welcome "Welcome to FastMCP 2.0! - FastMCP"
[6]: https://nmap.org/book/inst-windows.html?utm_source=chatgpt.com "Windows | Nmap Network Scanning"
[7]: https://ollama.com/library/qwen3/tags?utm_source=chatgpt.com "Tags · qwen3"
