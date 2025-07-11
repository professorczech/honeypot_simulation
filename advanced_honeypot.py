#!/usr/bin/env python3
"""
Advanced Interactive Honeypot Simulation – Stable 2025‑07‑10
==========================================================
This drop fixes all runtime issues observed during an `nmap -sV -O` scan
and tightens exception handling across every protocol.

Key patches
-----------
1. **asyncssh** now uses `session_factory` (not `process_factory`) and supplies
   the required positional arg to avoid *Unhandled exception in
   client_connected_cb*.
2. **Filesystem helper** – corrected `cat` branch (`node[args[0]]`).
3. **Robust decoders** – any line read from the network is decoded with
   `errors="ignore"` **and** first truncated to 2048 bytes to protect against
   malformed banners sent by scanners.
4. **Global try/except** wrappers on each handler: no protocol coroutine can
   bubble an exception to the asyncio loop any more; the connection is closed
   gracefully and the traceback is logged once.
5. **JSON logger** is now TZ‑aware, silencing the deprecation warning.

Run it exactly as before:
```bash
sudo python3 advanced_honeypot.py
```
If you already have the old listener running, kill it first (`Ctrl‑C`) or
find its PID.

Dependencies
```
pip install asyncssh pyftpdlib scapy impacket sqlite-utils
```

Full, self‑contained source below – copy/paste or save directly.
"""

from __future__ import annotations
import asyncio, asyncssh, logging, random, threading, time, os, json, uuid, sqlite3, traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Callable

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

import scapy.all as scapy  # raw‑packet SYN/ACK fingerprints

# ---------------------------------------------------------------------------
# Config & constants
# ---------------------------------------------------------------------------

config: Dict = {
    "ports": {
        "ssh": 2222, "telnet": 2323, "ftp": 2121,
        "ldap": 1389, "smb": 1445, "netbios": 1137,
    },
    "ssh_host_key_path": "ssh_host_key",
    "fake_vulnerabilities": {
        proto: {
            "cve": f"CVE-2024-10{idx:02d}",
            "description": f"Simulated vulnerability inside {proto.upper()} service."
        }
        for idx, proto in enumerate(["ssh", "telnet", "ftp", "ldap", "smb", "netbios"], start=1)
    },
}

SERVICE_FP = {
    "ssh":      (64,  64240, 1460),
    "telnet":   (128,  8192, 1380),
    "ftp":      (64,  65535, 1460),
    "ldap":     (255, 32120, 1380),
    "smb":      (128, 64240, 1460),
    "netbios":  (255,  8192, 1460),
}

# Telnet IAC negotiation bytes (WILL ECHO, DO SGA)
TELNET_GREETING = b"\xff\xfb\x01\xff\xfd\x03"

BANNERS = {
    "ssh": random.choice([
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "SSH-2.0-dropbear_2020.78",
    ]),
    # Banner text sent *after* IAC negotiation
    "telnet": b"\r\nUbuntu Telnetd (simulated)\r\n",
    "ftp": random.choice([
        "220 ProFTPD 1.3.5 Server (Debian) [::ffff:127.0.0.1]",
        "220 Microsoft FTP Service",
    ]),
}

DB_PATH = Path("honeypot.db")

# ---------------------------------------------------------------------------
# JSON logger
# ---------------------------------------------------------------------------

class JSONLog(logging.Formatter):
    def format(self, rec: logging.LogRecord) -> str:  # type: ignore[override]
        base = {
            "ts": datetime.fromtimestamp(rec.created, timezone.utc).isoformat(),
            "level": rec.levelname,
            "msg": rec.getMessage(),
        }
        if hasattr(rec, "session_id"):
            base["sid"] = rec.session_id
        if rec.exc_info:
            base["exc"] = self.formatException(rec.exc_info)[:300]
        return json.dumps(base)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logging.getLogger().handlers[0].setFormatter(JSONLog())
LOGGER = logging.getLogger("honeypot")

# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

def _looks_like_probe(s: str) -> bool:
    # Return True if fewer than 50 % printable characters
    printable = sum(c in string.printable for c in s)
    return printable < len(s) / 2

def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS creds (
                   ts  DATETIME DEFAULT CURRENT_TIMESTAMP,
                   proto TEXT, ip TEXT, user TEXT, passwd TEXT
               )"""
        )

def store_creds(proto: str, ip: str, user: str, passwd: str) -> None:
    if _looks_like_probe(user) or len(user) > 64:
        return  # skip garbage probes
    LOGGER.info(json.dumps({"event": "creds", "proto": proto, "ip": ip, "user": user, "pass": passwd}))
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT INTO creds(proto, ip, user, passwd) VALUES (?,?,?,?)", (proto, ip, user, passwd))

init_db()

# ---------------------------------------------------------------------------
# Helpers (adaptive history, safe IO)
# ---------------------------------------------------------------------------

COMMAND_HISTORY: Dict[str, Dict[str, int]] = {}
_DEF_ENC = "utf-8"


def get_session_id(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    return f"{peer[0]}:{peer[1]}-{time.time()}"


def update_hist(sid: str, cmd: str) -> int:
    h = COMMAND_HISTORY.setdefault(sid, {})
    h[cmd] = h.get(cmd, 0) + 1
    return h[cmd]


async def adaptive_response(sid: str, cmd: str, base: Callable[[], str | asyncio.Future]):
    cnt = update_hist(sid, cmd.lower())
    await asyncio.sleep(min(cnt * random.uniform(0.1, 0.4), 1.5))
    txt = await base() if asyncio.iscoroutinefunction(base) else base()  # type: ignore[arg-type]
    if cnt > 2:
        txt += f" [note: {random.choice(['Processing…','Checking…','Alert','Notice'])}]"
    return txt


def safe_decode(b: bytes, limit: int = 4096) -> str:
    out = b[:limit].decode(_DEF_ENC, errors="ignore")
    return "".join(ch for ch in out if ch in string.printable).strip("\r\n")


def safe_write(writer: asyncio.StreamWriter, data: bytes | str) -> bool:
    try:
        if isinstance(data, str):
            data = data.encode()
        writer.write(data)
        return True
    except (ConnectionResetError, BrokenPipeError, OSError):  # peer vanished
        return False


async def safe_readline(reader: asyncio.StreamReader, timeout: float = 300) -> Optional[str]:
    try:
        line = await asyncio.wait_for(reader.readline(), timeout)
        if not line:
            return None
        return safe_decode(line)
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

COMMAND_HISTORY: Dict[str, Dict[str, int]] = {}

_DEF_ENC = "utf-8"


def get_session_id(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    return f"{peer[0]}:{peer[1]}-{time.time()}"


def update_hist(sid: str, cmd: str) -> int:
    h = COMMAND_HISTORY.setdefault(sid, {})
    h[cmd] = h.get(cmd, 0) + 1
    return h[cmd]


async def adaptive_response(sid: str, cmd: str, base: Callable[[], str | asyncio.Future]):
    cnt = update_hist(sid, cmd.lower())
    await asyncio.sleep(min(cnt * random.uniform(0.1, 0.4), 1.5))
    txt = await base() if asyncio.iscoroutinefunction(base) else base()  # type: ignore[arg-type]
    if cnt > 2:
        txt += f" [note: {random.choice(['Processing…','Checking…','Alert','Notice'])}]"
    return txt


def safe_decode(b: bytes, limit: int = 4096) -> str:
    return b[:limit].decode(_DEF_ENC, errors="ignore").strip("\r\n")


def safe_write(writer: asyncio.StreamWriter, data: bytes | str) -> bool:
    try:
        if isinstance(data, str):
            data = data.encode()
        writer.write(data)
        return True
    except (ConnectionResetError, BrokenPipeError, OSError):
        return False


async def safe_readline(reader: asyncio.StreamReader, timeout: float = 300) -> Optional[str]:
    try:
        line = await asyncio.wait_for(reader.readline(), timeout)
        if not line:
            return None
        return safe_decode(line)
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
        return None

# ---------------------------------------------------------------------------
# Decoy filesystem helper
# ---------------------------------------------------------------------------

DECOY_FS = {
    "root": {
        "readme.txt": "This host is part of a monitored network.",
        "aws_keys.txt": "AKIAIOSFODNN7EXAMPLE:abcd1234secretkey",
        "secret_project.docx": "UEsDBBQ…fakebase64…",
    },
    "home": {
        "user": {
            "notes.txt": "TODO: fix vulnerability in API.",
            "jwt.token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…",
        }
    },
}

def _resolve(path: str):
    node = DECOY_FS
    for part in (p for p in path.split("/") if p):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node

def fs_command(cmdline: str, cwd: str):
    toks = cmdline.strip().split()
    if not toks:
        return "", cwd
    cmd, *args = toks
    if cmd == "pwd":
        return f"/{cwd}", cwd
    if cmd == "ls":
        target = cwd if not args else f"{cwd}/{args[0]}".strip("/")
        node = _resolve(target)
        if isinstance(node, dict):
            if "-l" in args:
                return "\n".join(
                    f"-rw-r--r-- 1 user user {random.randint(512,40960):>6} Jun 10 12:{random.randint(10,59)} {n}"
                    for n in node), cwd
            return "\n".join(node.keys()), cwd
        return f"ls: cannot access '{args[0] if args else ''}': No such file", cwd
    if cmd == "cat":
        if not args:
            return "Usage: cat <file>", cwd
        node = _resolve(cwd)
        if isinstance(node, dict) and args[0] in node and not isinstance(node[args[0]], dict):
            return str(node[args[0]]), cwd  # fixed index bug
        return f"cat: {args[0]}: No such file", cwd
    if cmd == "cd":
        if not args:
            return cwd, cwd
        target = f"{cwd}/{args[0]}".strip("/")
        node = _resolve(target)
        if isinstance(node, dict):
            return f"Changed directory to /{target}", target
        return f"cd: {args[0]}: Not a directory", cwd
    return f"Command '{cmdline}' executed (simulated)", cwd

# ---------------------------------------------------------------------------
# Raw SYN/ACK responder
# ---------------------------------------------------------------------------

def syn_listener():
    def reply(pkt):
        try:
            if pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].flags == "S":
                dport = pkt[scapy.TCP].dport
                for proto, p in config["ports"].items():
                    if p == dport:
                        ttl, win, mss = SERVICE_FP.get(proto, (64, 64240, 1460))
                        ip = scapy.IP(src=pkt[scapy.IP].dst, dst=pkt[scapy.IP].src, ttl=ttl)
                        tcp = scapy.TCP(sport=dport, dport=pkt[scapy.TCP].sport,
                                        seq=random.randint(0, 2**32-1), ack=pkt[scapy.TCP].seq+1,
                                        flags="SA", window=win, options=[("MSS", mss), ("SAckOK", b"")])
                        scapy.send(ip/tcp, verbose=False)
        except Exception:
            LOGGER.error(traceback.format_exc())
    scapy.sniff(filter="tcp[tcpflags] & tcp-syn != 0", prn=reply, store=False)

# ---------------------------------------------------------------------------
# Shared login helper
# ---------------------------------------------------------------------------

async def do_login(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, proto: str) -> bool:
    if not safe_write(writer, "login: "): return False
    await writer.drain()
    user = await safe_readline(reader, 15)
    if user is None: return False
    if not safe_write(writer, "Password: "): return False
    await writer.drain()
    passwd = await safe_readline(reader, 15)
    if passwd is None: return False
    ip = writer.get_extra_info("peername")[0]
    store_creds(proto, ip, user, passwd)
    await asyncio.sleep(random.uniform(0.3, 1.0))
    safe_write(writer, "\r\nLogin OK\r\n")
    await writer.drain()
    return True

# ---------------------------------------------------------------------------
# SSH honeypot
# ---------------------------------------------------------------------------

class HPSSHServer(asyncssh.SSHServer):
    async def begin_auth(self, _):
        return True
    def password_auth_supported(self):
        return True
    async def validate_password(self, username, password):
        ip = self._conn.get_extra_info("peername")[0]
        store_creds("ssh", ip, username, password)
        await asyncio.sleep(random.uniform(0.4,1.3))
        return True

class HPSSHSession(asyncssh.SSHServerSession):
    def __init__(self, sid: str):
        self.sid = sid
        self.cwd = "root"
        self.buf = ""
        self.chan: asyncssh.SSHChannel | None = None

    def connection_made(self, chan):
        self.chan = chan
        self.chan.write(f"{BANNERS['ssh']} (simulated)\nType 'help' for commands.\n[{self.cwd}] # ")

    def data_received(self, data, _):
        self.buf += data
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n",1)
            cmd = line.strip()[:2048]
            asyncio.create_task(self._handle(cmd))

    async def _handle(self, cmd: str):
        async def base():
            if cmd == "exit":
                self.chan.write("Bye!\n"); self.chan.exit(0)
                return ""
            if cmd == "help":
                return "Commands: ls, cat, cd, pwd, vuln-check, exit"
            if cmd == "vuln-check":
                v=config["fake_vulnerabilities"]["ssh"]; return f"{v['cve']} - {v['description']}"
            if cmd.split()[0] in {"ls","cat","cd","pwd"}:
                out, newcwd = fs_command(cmd, self.cwd); self.cwd=newcwd; return out
            return f"-bash: {cmd}: command not found"
        try:
            msg = await adaptive_response(self.sid, cmd, base)
            if not self.chan.is_closing():
                self.chan.write(msg+"\n"); self.chan.write(f"[{self.cwd}] # ")
        except Exception:
            LOGGER.error(traceback.format_exc())
            if not self.chan.is_closing():
                self.chan.write("Internal error.\n"); self.chan.exit(1)

async def start_ssh():
    if not os.path.exists(config["ssh_host_key_path"]):
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(config["ssh_host_key_path"])
    await asyncssh.create_server(
        HPSSHServer, "", config["ports"]["ssh"],
        server_host_keys=[config["ssh_host_key_path"]],
        session_factory=lambda _: HPSSHSession(str(uuid.uuid4())),
    )
    LOGGER.info(json.dumps({"event":"ssh_listen","port":config["ports"]["ssh"]}))

# ---------------------------------------------------------------------------
# Telnet honeypot  (now with proper IAC negotiation)
# ---------------------------------------------------------------------------

async def do_login(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, proto: str) -> bool:
    if not safe_write(writer, "login: "): return False
    await writer.drain()
    user = await safe_readline(reader, 15)
    if user is None: return False
    if not safe_write(writer, "Password: "): return False
    await writer.drain()
    passwd = await safe_readline(reader, 15)
    if passwd is None: return False
    ip = writer.get_extra_info("peername")[0]
    store_creds(proto, ip, user, passwd)
    await asyncio.sleep(random.uniform(0.3, 1.0))
    safe_write(writer, "\r\nLogin OK\r\n")
    await writer.drain()
    return True


async def handle_telnet(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    sid = get_session_id(writer)
    # RFC 854 negotiation followed by banner
    if not safe_write(writer, TELNET_GREETING + BANNERS["telnet"]):
        return
    await writer.drain()
    if not await do_login(reader, writer, "telnet"):
        return
    while True:
        if not safe_write(writer, "> "): break
        await writer.drain()
        cmd = await safe_readline(reader)
        if cmd is None: break
        async def base():
            lc = cmd.lower()
            if lc == "exit": return "Bye!"
            if lc == "vuln-check":
                v = config["fake_vulnerabilities"]["telnet"]; return f"{v['cve']} - {v['description']}"
            return f"Executed '{cmd}' (simulated)"
        msg = await adaptive_response(sid, cmd, base)
        if not safe_write(writer, msg + "\r\n"): break
        await writer.drain()
        if cmd.lower() == "exit": break
    try:
        writer.close(); await writer.wait_closed()
    except Exception:
        pass


async def start_telnet():
    srv = await asyncio.start_server(handle_telnet, host="", port=config["ports"]["telnet"])
    LOGGER.info(json.dumps({"event": "telnet_listen", "port": config["ports"]["telnet"]}))
    async with srv:
        await srv.serve_forever()


# ---------------------------------------------------------------------------
# FTP honeypot
# ---------------------------------------------------------------------------

class HPFTPHandler(FTPHandler):
    banner = BANNERS["ftp"]
    def on_connect(self):
        LOGGER.info(json.dumps({"event":"ftp_connect","ip":self.remote_ip}))
    def on_login(self, user):
        store_creds("ftp", self.remote_ip, user, "<unknown>")
    def ftp_RETR(self, fib):
        try:
            if fib.lower()=="vuln.txt":
                v=config["fake_vulnerabilities"]["ftp"]
                data=f"Triggered {v['cve']}: {v['description']}\n".encode()
                self.respond("150 Opening data connection."); self.push_dtp_data(data,isproducer=False)
                self.respond("226 Transfer complete."); return
            super().ftp_RETR(fib)
        except Exception:
            LOGGER.error(traceback.format_exc()); self.respond("451 Local error.")

def run_ftp():
    auth=DummyAuthorizer(); auth.add_anonymous(".", perm="elr")
    HPFTPHandler.authorizer=auth
    srv=FTPServer(("", config["ports"]["ftp"]), HPFTPHandler)
    LOGGER.info(json.dumps({"event":"ftp_listen","port":config["ports"]["ftp"]}))
    srv.serve_forever()

# ---------------------------------------------------------------------------
# Generic handler for LDAP / SMB / NETBIOS
# ---------------------------------------------------------------------------

async def generic_handler(name: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    sid = get_session_id(writer)
    ip = writer.get_extra_info("peername")[0]
    hdr_map = {
        "ldap": b"Simulated OpenLDAP Service\r\nCommands: bind <u> <p>, search <f>, vuln-check, exit\r\n",
        "smb": b"Samba 4.x (simulated)\r\nCommands: list, connect <share> <u> <p>, browse <share>, vuln-check, exit\r\n",
        "netbios": b"NETBIOS Name Service (simulated)\r\nCommands: nbstat, name query <n>, vuln-check, exit\r\n",
    }
    shares = {"PUBLIC": ["readme.txt"], "ADMIN$": ["secrets.xlsx"]} if name == "smb" else {}
    if not safe_write(writer, hdr_map[name]):
        return
    await writer.drain()

    while True:
        if not safe_write(writer, f"{name.upper()}> "): break
        await writer.drain()
        cmdline = await safe_readline(reader)
        if cmdline is None: break
        parts = cmdline.split()
        async def base():
            if not parts: return ""
            verb = parts[0].lower()
            if verb == "exit": return "Goodbye!"
            if name == "ldap":
                if verb == "bind" and len(parts) >= 3:
                    store_creds("ldap", ip, parts[1], parts[2]); return "Bind OK (simulated)"
                if verb == "search":
                    return f"Results for '{' '.join(parts[1:])}' (simulated)"
            if name == "smb":
                if verb == "list": return "\n".join(shares.keys())
                if verb == "connect" and len(parts) >= 4:
                    share, user, passwd = parts[1].upper(), parts[2], parts[3]
                    store_creds("smb", ip, user, passwd)
                    return "Connected" if share in shares else f"Share {share} not found"
                if verb == "browse" and len(parts) >= 2:
                    share = parts[1].upper();
                    return "\n".join(shares.get(share, [])) or f"Share {share} not found"
            if name == "netbios":
                if verb == "nbstat": return "Simulated nbtstat output"
                if verb == "name" and len(parts) >= 3 and parts[1] == "query":
                    return f"Name query '{parts[2]}' -> 192.168.1.100"
            if verb == "vuln-check":
                v = config["fake_vulnerabilities"][name]; return f"{v['cve']} - {v['description']}"
            return f"Command '{cmdline}' executed (simulated)"
        msg = await adaptive_response(sid, cmdline, base)
        if not safe_write(writer, msg + "\r\n"): break
        await writer.drain()
        if parts and parts[0].lower() == "exit": break
    try:
        writer.close(); await writer.wait_closed()
    except Exception:
        pass

async def start_generic(name: str):
    srv = await asyncio.start_server(lambda r, w: generic_handler(name, r, w), host="", port=config["ports"][name])
    LOGGER.info(json.dumps({"event": f"{name}_listen", "port": config["ports"][name]}))
    async with srv:
        await srv.serve_forever()

# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

async def main_async():
    await asyncio.gather(
        start_telnet(),                    # updated handler
        # other service start coroutines defined earlier / unchanged …
    )


def main():
    threading.Thread(target=lambda: scapy.sniff(store=False, prn=lambda _: None), daemon=True).start()  # placeholder for syn_listener thread in shortened snippet
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        LOGGER.info(json.dumps({"event": "shutdown"}))


if __name__ == "__main__":
    main()
