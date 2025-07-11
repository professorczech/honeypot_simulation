#!/usr/bin/env python3
"""
Advanced Interactive Honeypot Simulation for Ethical‑Hacking Training
--------------------------------------------------------------------

Simulated Services  : SSH, Telnet, FTP, LDAP, SMB, NETBIOS
Extra Deception     : Raw‑socket SYN/ACK fingerprints, rotating banners, tarpit handshakes,
                      credential capture & replay (SQLite), adaptive delays, JSON logging

Ports (default)     : SSH 2222 | Telnet 2323 | FTP 2121 | LDAP 1389 | SMB 1445 | NETBIOS 1137

Usage               : sudo python3 advanced_honeypot.py
                      # root or CAP_NET_RAW required for raw‑socket listener

This file is **self‑contained**.  External deps:  asyncssh, pyftpdlib, scapy, impacket, sqlite3
"""

# ---------------------------------------------------------------------------
# Imports & Globals
# ---------------------------------------------------------------------------

import asyncio, asyncssh, logging, random, threading, time, os, json, uuid, sqlite3
from datetime import datetime
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

import scapy.all as scapy  # raw‑packet SYN/ACK fingerprints

DB_PATH = Path("honeypot.db")

# ----------------------------------------------------------------------------
# Configuration  (editable)
# ----------------------------------------------------------------------------

config = {
    "ports": {"ssh": 2222, "telnet": 2323, "ftp": 2121, "ldap": 1389, "smb": 1445, "netbios": 1137},
    "ssh_host_key_path": "ssh_host_key",
    "fake_vulnerabilities": {
        "ssh":     {"cve": "CVE-2024-1001", "description": "Simulated buffer overflow in SSH authentication."},
        "telnet":  {"cve": "CVE-2024-1002", "description": "Simulated command injection vulnerability."},
        "ftp":     {"cve": "CVE-2024-1003", "description": "Simulated directory traversal via vuln.txt."},
        "ldap":    {"cve": "CVE-2024-1004", "description": "Simulated LDAP injection vulnerability."},
        "smb":     {"cve": "CVE-2024-1005", "description": "Simulated SMB RCE vulnerability."},
        "netbios": {"cve": "CVE-2024-1006", "description": "Simulated NETBIOS info disclosure."}
    },
}

# SYN/ACK fingerprints per service (ttl, window, mss)
SERVICE_FP = {
    "ssh":  (64, 64240, 1460),
    "telnet": (128, 8192, 1380),
    "ftp":  (64, 65535, 1460),
    "ldap": (255, 32120, 1380),
    "smb":  (128, 64240, 1460),
    "netbios": (255, 8192, 1460),
}

# Banners picked once per startup (realism)
BANNERS = {
    "ssh": random.choice([
        "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "SSH-2.0-dropbear_2020.78"
    ]),
    "telnet": random.choice([
        b"Welcome to Generic Telnet Service (Ubuntu Linux)\r\n",
        b"RouterX Telnet Interface - Unauthorized access prohibited.\r\n"
    ]),
    "ftp": random.choice([
        "220 ProFTPD 1.3.5 Server (Debian) [::ffff:127.0.0.1]",
        "220 vsftpd 3.0.3 ready.",
        "220 Microsoft FTP Service"
    ])
}

# ---------------------------------------------------------------------------
# Logging: structured JSON  (easy to ship into ELK)
# ---------------------------------------------------------------------------

class JSONLog(logging.Formatter):
    def format(self, rec):
        base = {
            "ts": datetime.utcfromtimestamp(rec.created).isoformat() + "Z",
            "level": rec.levelname,
            "msg": rec.getMessage(),
        }
        if hasattr(rec, "session_id"):
            base["sid"] = rec.session_id
        return json.dumps(base)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logging.getLogger().handlers[0].setFormatter(JSONLog())
LOGGER = logging.getLogger("honeypot")

# ---------------------------------------------------------------------------
# SQLite helper for credential capture / replay
# ---------------------------------------------------------------------------

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS creds (
            ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            proto TEXT, ip TEXT, user TEXT, passwd TEXT
        )""")


def store_creds(proto: str, ip: str, user: str, passwd: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT INTO creds(proto, ip, user, passwd) VALUES (?,?,?,?)",
                     (proto, ip, user, passwd))

# ---------------------------------------------------------------------------
# Adaptive command history (per‑session)
# ---------------------------------------------------------------------------

COMMAND_HISTORY: dict[str, dict[str,int]] = {}

def get_session_id(writer):
    try:
        peer = writer.get_extra_info("peername")
        return f"{peer[0]}:{peer[1]}-{time.time()}"
    except Exception:
        return f"unknown-{time.time()}"

def update_hist(sid: str, cmd: str) -> int:
    h = COMMAND_HISTORY.setdefault(sid, {})
    h[cmd] = h.get(cmd, 0) + 1
    return h[cmd]

async def adaptive_response(sid: str, cmd: str, base_corofunc):
    count = update_hist(sid, cmd.lower())
    await asyncio.sleep(min(count * random.uniform(0.1,0.4), 1.5))
    suffix = f" [note: {random.choice(['Processing…','Checking…','Alert','Notice'])}]" if count>2 else ""
    txt = await base_corofunc()
    return txt + suffix

# ---------------------------------------------------------------------------
# Decoy filesystem (same as previous, trimmed)
# ---------------------------------------------------------------------------

DECOY_FS = {
    "root": {
        "readme.txt": "Welcome to the honeypot. This system is monitored.",
        "aws_keys.txt": "AKIAIOSFODNN7EXAMPLE:abcd1234secretkey",
        "system.conf": "SERVICE_PORT=8080\nADMIN_EMAIL=admin@example.com",
        "secret_project.docx": "UEsDBBQ…fakebase64payload…"
    },
    "home": {
        "user": {
            "notes.txt": "Meeting notes…",
            "jwt.token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…"
        }
    }
}

# ---------------------------------------------------------------------------
# Raw‑socket SYN listener (packet‑level fingerprinting)
# ---------------------------------------------------------------------------

def syn_listener():
    def reply(pkt):
        if pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].flags == "S":
            dport = pkt[scapy.TCP].dport
            for name, p in config["ports"].items():
                if p == dport:
                    ttl, window, mss = SERVICE_FP.get(name, (64, 64240, 1460))
                    ip = scapy.IP(src=pkt[scapy.IP].dst, dst=pkt[scapy.IP].src, ttl=ttl)
                    tcp = scapy.TCP(sport=dport, dport=pkt[scapy.TCP].sport,
                                    seq=random.randint(0, 2**32-1), ack=pkt[scapy.TCP].seq+1,
                                    flags="SA", window=window,
                                    options=[("MSS", mss), ("SAckOK", b"")])
                    scapy.send(ip/tcp, verbose=False)
    scapy.sniff(filter="tcp[tcpflags] & tcp-syn != 0", prn=reply, store=False)

# ---------------------------------------------------------------------------
# Filesystem command sim (ls, cat, cd, pwd)
# ---------------------------------------------------------------------------

def _resolve(path):
    parts = [p for p in path.split("/") if p]
    node = DECOY_FS
    for p in parts:
        if isinstance(node, dict) and p in node:
            node = node[p]
        else:
            return None
    return node

def fs_command(cmdline: str, cwd: str="root"):
    tokens = cmdline.strip().split()
    if not tokens:
        return "", cwd
    cmd, *args = tokens
    if cmd == "pwd":
        return f"/{cwd}", cwd
    if cmd == "ls":
        target = cwd if not args else f"{cwd}/{args[0]}".strip("/")
        node = _resolve(target)
        if isinstance(node, dict):
            if "-l" in args:
                out = []
                for name in node:
                    size = random.randint(512, 40960)
                    out.append(f"-rw-r--r-- 1 user user {size:>6} Jun 10 12:{random.randint(10,59)} {name}")
                return "\n".join(out), cwd
            return "\n".join(node.keys()), cwd
        return f"ls: cannot access '{args[0] if args else ''}': No such file or directory", cwd
    if cmd == "cat":
        if not args:
            return "Usage: cat <file>", cwd
        node = _resolve(cwd)
        if isinstance(node, dict) and args[0] in node and not isinstance(node[args[0]], dict):
            return str(node[args[0]]), cwd
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
# SSH Honeypot (asyncssh)
# ---------------------------------------------------------------------------

class HPSSHServer(asyncssh.SSHServer):
    async def begin_auth(self, username):
        # Accept all; capture creds on password method
        return True

    def password_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        peer = self._conn.get_extra_info("peername")[0]
        store_creds("ssh", peer, username, password)
        await asyncio.sleep(random.uniform(0.4,1.2))  # tarpit delay
        return True

class HPSSHSession(asyncssh.SSHServerSession):
    def __init__(self, sid):
        super().__init__()
        self.sid = sid
        self._buf = ""
        self.cwd = "root"

    def connection_made(self, chan):
        self.chan = chan
        ttl, win, _ = SERVICE_FP["ssh"]
        self.chan.write(f"Welcome! [{BANNERS['ssh']}]\n")
        self.chan.write(f"[System] TCP Fingerprint: TTL={ttl} Window={win}\n")
        self.chan.write("Type 'help' for commands, 'exit' to quit.\n")
        self.chan.write(f"[{self.cwd}] # ")

    def data_received(self, data, _):
        self._buf += data
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n",1)
            cmd = line.strip()
            if cmd:
                asyncio.create_task(self._handle(cmd))

    async def _handle(self, cmd):
        async def base():
            lower = cmd.lower()
            if lower == "exit":
                self.chan.write("Goodbye!\n")
                self.chan.exit(0)
                return "Goodbye!"
            if lower == "help":
                return "Available: ls, cat, cd, pwd, vuln-check, exit"
            if lower == "vuln-check":
                v = config["fake_vulnerabilities"]["ssh"]
                return f"Vulnerability detected: {v['cve']} - {v['description']}"
            if lower.split()[0] in ("ls","cat","cd","pwd"):
                resp, newcwd = fs_command(cmd, self.cwd)
                self.cwd = newcwd
                return resp
            return f"-bash: {cmd.split()[0]}: command not found"
        out = await adaptive_response(self.sid, cmd, base)
        if not self.chan.is_closing():
            self.chan.write(out + "\n")
            self.chan.write(f"[{self.cwd}] # ")

async def start_ssh():
    key_path = Path(config["ssh_host_key_path"])
    if not key_path.exists():
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(key_path))
    await asyncssh.create_server(
        HPSSHServer, host="", port=config["ports"]["ssh"],
        server_host_keys=[str(key_path)],
        process_factory=lambda conn: HPSSHSession(sid=f"ssh-{conn.get_extra_info('peername')[0]}-{time.time()}")
    )
    LOGGER.info(json.dumps({"service":"ssh","status":"listening","port":config["ports"]["ssh"]}))

# ---------------------------------------------------------------------------
# Telnet Honeypot (plain asyncio)
# ---------------------------------------------------------------------------

async def telnet_login(r, w, ip):
    w.write(b"login: "); await w.drain()
    user = (await r.readline())[:32].decode(errors='ignore').strip()
    w.write(b"Password: "); await w.drain()
    pwd = (await r.readline())[:32].decode(errors='ignore').strip()
    store_creds("telnet", ip, user, pwd)
    await asyncio.sleep(random.uniform(0.5,1.2))
    w.write(b"\r\nLogin OK\r\n")

async def handle_telnet(r, w):
    ip = w.get_extra_info("peername")[0]
    sid = get_session_id(w)
    w.write(BANNERS["telnet"]); await w.drain()
    await telnet_login(r, w, ip)
    w.write(b"Type 'vuln-check' or 'exit'.\r\n")
    while True:
        w.write(b"> "); await w.drain()
        try:
            data = await asyncio.wait_for(r.readline(), 300)
        except asyncio.TimeoutError:
            break
        if not data:
            break
        cmd = data.decode(errors='ignore').strip()
        if not cmd:
            continue
        async def base():
            lc = cmd.lower()
            if lc == "exit":
                return "Goodbye!"
            if lc == "vuln-check":
                v=config["fake_vulnerabilities"]["telnet"]
                return f"Vulnerability detected: {v['cve']} - {v['description']}"
            if lc in ("ls","dir","status"):
                return f"Simulated output for '{cmd}'."
            return f"Command '{cmd}' executed (simulated)."
        out = await adaptive_response(sid, cmd, base)
        w.write(out.encode()+b"\r\n"); await w.drain()
        if cmd.lower()=="exit":
            break
    w.close(); await w.wait_closed()

async def start_telnet():
    srv = await asyncio.start_server(handle_telnet, host="", port=config["ports"]["telnet"])
    LOGGER.info(json.dumps({"service":"telnet","status":"listening","port":config["ports"]["telnet"]}))
    async with srv:
        await srv.serve_forever()

# ---------------------------------------------------------------------------
# FTP Honeypot (pyftpdlib)
# ---------------------------------------------------------------------------

class HPFTPHandler(FTPHandler):
    def on_connect(self):
        LOGGER.info(json.dumps({"service":"ftp","event":"connect","ip":self.remote_ip}))
    def on_login(self, user):
        store_creds("ftp", self.remote_ip, user, "<unknown>")
    def ftp_RETR(self, file):
        if file.lower()=="vuln.txt":
            v=config["fake_vulnerabilities"]["ftp"]
            self.respond("150 opening data connection")
            self.push_dtp_data((f"Triggered! {v['cve']} {v['description']}\n").encode(), isproducer=False)
            self.respond("226 transfer complete")
        else:
            super().ftp_RETR(file)


def start_ftp_thread():
    authorizer=DummyAuthorizer(); authorizer.add_anonymous(".", perm="elr")
    HPFTPHandler.authorizer=authorizer; HPFTPHandler.banner=BANNERS["ftp"]+"\r\n"
    HPFTPHandler.passive_ports=range(60000,60010)
    srv=FTPServer(("",config["ports"]["ftp"]), HPFTPHandler)
    LOGGER.info(json.dumps({"service":"ftp","status":"listening","port":config["ports"]["ftp"]}))
    srv.serve_forever()

def run_ftp():
    threading.Thread(target=start_ftp_thread, daemon=True).start()

# ---------------- LDAP ----------------

async def handle_ldap(reader, writer):
    ip = writer.get_extra_info("peername")[0]
    sid = get_session_id(writer)
    writer.write(b"Simulated OpenLDAP Service\r\n")
    writer.write(b"Commands: bind <user> <pass>, search <filter>, vuln-check, exit\r\n")
    await writer.drain()

    while True:
        writer.write(b"LDAP> ")
        await writer.drain()
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=300)
        except asyncio.TimeoutError:
            break
        if not line:
            break
        cmdline = line.decode(errors="ignore").strip()
        parts = cmdline.split()

        async def base():
            if not parts:
                return ""
            verb = parts[0].lower()
            if verb == "exit":
                return "Goodbye!"
            if verb == "bind" and len(parts) >= 3:
                user, passwd = parts[1], parts[2]
                store_creds("ldap", ip, user, passwd)
                return "Bind successful (simulated)"
            if verb == "search":
                return f"Simulated results for filter '{' '.join(parts[1:])}' (2 entries)"
            if verb == "vuln-check":
                v = config["fake_vulnerabilities"]["ldap"]
                return f"{v['cve']} - {v['description']}"
            return f"Command '{cmdline}' executed (simulated)"
        msg = await adaptive_response(sid, cmdline, base)
        writer.write(msg.encode() + b"\r\n")
        await writer.drain()
        if parts and parts[0].lower() == "exit":
            break
    writer.close()
    await writer.wait_closed()

async def start_ldap():
    srv = await asyncio.start_server(handle_ldap, host="", port=config["ports"]["ldap"])
    LOGGER.info(json.dumps({"event": "ldap_listen", "port": config["ports"]["ldap"]}))
    async with srv:
        await srv.serve_forever()

# ---------------- SMB ----------------

async def handle_smb(reader, writer):
    ip = writer.get_extra_info("peername")[0]
    sid = get_session_id(writer)
    shares = {"PUBLIC": ["readme.txt", "docs.zip"], "ADMIN$": ["secrets.xlsx"]}

    writer.write(b"Samba 4.x (simulated)\r\n")
    writer.write(b"Commands: list, connect <share> <user> <pass>, browse <share>, vuln-check, exit\r\n")
    await writer.drain()

    while True:
        writer.write(b"SMB> ")
        await writer.drain()
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=300)
        except asyncio.TimeoutError:
            break
        if not line:
            break
        cmdline = line.decode(errors="ignore").strip()
        parts = cmdline.split()

        async def base():
            if not parts:
                return ""
            verb = parts[0].lower()
            if verb == "exit":
                return "Bye!"
            if verb == "list":
                return "\n".join(shares.keys())
            if verb == "connect" and len(parts) >= 4:
                share, user, passwd = parts[1].upper(), parts[2], parts[3]
                store_creds("smb", ip, user, passwd)
                if share in shares:
                    return f"Connected to {share} (simulated). Use 'browse {share}'."
                return f"Share {share} not found"
            if verb == "browse" and len(parts) >= 2:
                share = parts[1].upper()
                if share in shares:
                    return "\n".join(shares[share])
                return f"Share {share} not found"
            if verb == "vuln-check":
                v = config["fake_vulnerabilities"]["smb"]
                return f"{v['cve']} - {v['description']}"
            return f"Command '{cmdline}' executed (simulated)"
        msg = await adaptive_response(sid, cmdline, base)
        writer.write(msg.encode() + b"\r\n")
        await writer.drain()
        if parts and parts[0].lower() == "exit":
            break
    writer.close()
    await writer.wait_closed()

async def start_smb():
    srv = await asyncio.start_server(handle_smb, host="", port=config["ports"]["smb"])
    LOGGER.info(json.dumps({"event": "smb_listen", "port": config["ports"]["smb"]}))
    async with srv:
        await srv.serve_forever()

# ---------------- NETBIOS ----------------

async def handle_netbios(reader, writer):
    ip = writer.get_extra_info("peername")[0]
    sid = get_session_id(writer)
    writer.write(b"NETBIOS Name Service (simulated)\r\n")
    writer.write(b"Commands: nbstat, name query <name>, vuln-check, exit\r\n")
    await writer.drain()

    while True:
        writer.write(b"NETBIOS> ")
        await writer.drain()
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=300)
        except asyncio.TimeoutError:
            break
        if not line:
            break
        cmdline = line.decode(errors="ignore").strip()
        parts = cmdline.split()

        async def base():
            if not parts:
                return ""
            verb = parts[0].lower()
            if verb == "exit":
                return "Bye!"
            if verb == "nbstat":
                return "Simulated nbtstat output (2 names)"
            if verb == "name" and len(parts) >= 3 and parts[1] == "query":
                return f"Name query result for '{parts[2]}': 192.168.1.100 (simulated)"
            if verb == "vuln-check":
                v = config["fake_vulnerabilities"]["netbios"]
                return f"{v['cve']} - {v['description']}"
            return f"Command '{cmdline}' executed (simulated)"
        msg = await adaptive_response(sid, cmdline, base)
        writer.write(msg.encode() + b"\r\n")
        await writer.drain()
        if parts and parts[0].lower() == "exit":
            break
    writer.close()
    await writer.wait_closed()

async def start_netbios():
    srv = await asyncio.start_server(handle_netbios, host="", port=config["ports"]["netbios"])
    LOGGER.info(json.dumps({"event": "netbios_listen", "port": config["ports"]["netbios"]}))
    async with srv:
        await srv.serve_forever()

async def dummy_handler(name, reader, writer):
    ip = writer.get_extra_info("peername")[0]
    sid = get_session_id(writer)
    writer.write(f"Welcome to simulated {name}. Type 'vuln-check' or 'exit'.\r\n".encode()); await writer.drain()
    while True:
        writer.write(f"{name}> ".encode()); await writer.drain()
        try:
            data = await asyncio.wait_for(reader.readline(),300)
        except asyncio.TimeoutError:
            break
        if not data:
            break
        cmd=data.decode(errors='ignore').strip()
        async def base():
            if cmd.lower()=="exit":
                return "Goodbye!"
            if cmd.lower()=="vuln-check":
                v=config["fake_vulnerabilities"][name]
                return f"Vulnerability: {v['cve']} - {v['description']}"
            return f"Command '{cmd}' executed (simulated)"
        out=await adaptive_response(sid, cmd, base)
        writer.write(out.encode()+b"\r\n"); await writer.drain()
        if cmd.lower()=="exit":
            break
    writer.close(); await writer.wait_closed()

async def start_generic(name):
    srv = await asyncio.start_server(lambda r,w: dummy_handler(name,r,w), host="", port=config["ports"][name])
    LOGGER.info(json.dumps({"service":name,"status":"listening","port":config["ports"][name]}))
    async with srv:
        await srv.serve_forever()

# ---------------------------------------------------------------------------
# Main async orchestrator
# ---------------------------------------------------------------------------

async def main_async():
    tasks = [
        asyncio.create_task(start_ssh()),
        asyncio.create_task(start_telnet()),
        asyncio.create_task(start_ldap()),
        asyncio.create_task(start_smb()),
        asyncio.create_task(start_netbios()),
    ]
    await asyncio.gather(*tasks)


def main():
    threading.Thread(target=syn_listener, daemon=True).start()
    threading.Thread(target=start_ftp_thread, daemon=True).start()
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        LOGGER.info(json.dumps({"event": "shutdown"}))


if __name__ == "__main__":
    main()

