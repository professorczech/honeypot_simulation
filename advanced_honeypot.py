#!/usr/bin/env python3
"""
Advanced Interactive Honeypot Simulation for Ethical Hacking Training

Simulated Services: SSH, Telnet, FTP, LDAP, SMB, NETBIOS

Features:
  - Listens on non-default ports.
  - Provides randomized/fake banners.
  - Simulates TCP/IP parameters (SSH).
  - Offers interactive shells for text-based protocols.
  - Includes decoy file systems (SSH) and shares (SMB).
  - Implements adaptive responses (delays/notes on repeated commands).
  - Supports multi-step interactions (LDAP, SMB).
  - Responds to 'vuln-check' trigger (or RETR vuln.txt for FTP) with simulated vulnerability messages.

Ports configuration (adjustable):
  - SSH:     2222
  - Telnet:  2323
  - FTP:     2121
  - LDAP:    1389
  - SMB:     1445
  - NETBIOS: 1137
"""

import asyncio
import asyncssh
import logging
import random
import threading
import time
import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# --- Configuration ---

config = {
    "ports": {
        "ssh": 2222,
        "telnet": 2323,
        "ftp": 2121,
        "ldap": 1389,
        "smb": 1445,
        "netbios": 1137,
    },
    "fake_vulnerabilities": {
        "ssh": {"cve": "CVE-2024-1001", "description": "Simulated buffer overflow in SSH authentication."},
        "telnet": {"cve": "CVE-2024-1002", "description": "Simulated command injection vulnerability in Telnet service."},
        "ftp": {"cve": "CVE-2024-1003", "description": "Simulated directory traversal vulnerability via vuln.txt retrieval."},
        "ldap": {"cve": "CVE-2024-1004", "description": "Simulated LDAP injection vulnerability during search."},
        "smb": {"cve": "CVE-2024-1005", "description": "Simulated SMB remote code execution vulnerability (fake)."},
        "netbios": {"cve": "CVE-2024-1006", "description": "Simulated NETBIOS information disclosure vulnerability (fake)."}
    },
    "ssh_host_key_path": "ssh_host_key" # Path for the SSH host key
}

# --- Global State & Helpers ---

# Global command history per session for adaptive responses.
# Maps session_id to a dictionary {command: count}
command_history = {}

def get_session_id(writer):
    """Generates a unique session ID based on peer address and current time."""
    try:
        peer = writer.get_extra_info("peername")
        return f"{peer[0]}:{peer[1]}-{time.time()}"
    except Exception:
        return f"unknown-{time.time()}" # Fallback

def update_command_history(session_id, command):
    """Updates and retrieves the count for a command in a session."""
    if session_id not in command_history:
        command_history[session_id] = {}
    history = command_history[session_id]
    history[command] = history.get(command, 0) + 1
    # Clean up old sessions periodically (optional, basic implementation)
    if len(command_history) > 1000:
       keys_to_delete = [k for k, v in command_history.items() if time.time() - float(k.split('-')[-1]) > 3600] # 1 hour expiry
       for k in keys_to_delete:
           del command_history[k]
    return history[command]

async def adaptive_response(session_id, command, base_response_func):
    """
    Adds delay and randomization if a command is repeated within a session.
    base_response_func should be an async function or coroutine returning the base response string.
    """
    count = update_command_history(session_id, command.lower())
    extra_delay = min(count * random.uniform(0.1, 0.4), 1.5) # Cap delay
    randomized_suffix = ""
    if count > 2: # Add suffix after the second repeat
        randomized_suffix = f" [note: {random.choice(['Processing...', 'Checking...', 'Alert', 'Notice'])}]"

    await asyncio.sleep(extra_delay)
    base_response = await base_response_func() # Get the base response *after* the delay
    return base_response + randomized_suffix

# Simulated file system for SSH decoy data.
decoy_file_system = {
    "root": {
        "readme.txt": "Welcome to the honeypot simulation environment. This system is monitored.",
        "user_credentials.txt": "Username: testuser\nPassword: Password123!",
        "system.conf": "# System Configuration\nSERVICE_PORT=8080\nADMIN_EMAIL=admin@example.com",
        "secret_project.docx": "Project Phoenix Details: The objective is to deploy by Q4. Code name: Firebird."
    },
    "etc": {
        "passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nuser:x:1000:1000:Test User:/home/user:/bin/bash",
        "shadow": "root:$6$randomsalt$hash:18370:0:99999:7:::\ndaemon:*:18370:0:99999:7:::\nuser:$6$anothersalt$hash:18370:0:99999:7:::",
        "hosts": "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n192.168.1.100 fileserver"
    },
    "home/user": {
         "documents": {"report.pdf": "CONFIDENTIAL REPORT DATA...", "notes.txt": "Meeting notes..."},
         "downloads": {"installer.exe": "[Simulated binary data]", "archive.zip": "[Simulated zip data]"}
    }
}

def simulate_filesystem_command(command_line, current_dir_path="root"):
    """
    Simulates simple filesystem commands ('ls', 'cat', 'pwd', 'cd').
    Supports basic directory structure.
    Returns the command output string.
    """
    tokens = command_line.split()
    if not tokens:
        return "", current_dir_path # No command, return empty output and same path

    cmd = tokens[0].lower()
    args = tokens[1:]

    # Helper to get current directory content from path
    def get_dir_content(path_str):
        current_level = decoy_file_system
        if path_str == "": return current_level # Root edge case
        parts = path_str.split('/')
        try:
            for part in parts:
                if part: # Skip empty parts resulting from //
                   current_level = current_level[part]
            if not isinstance(current_level, dict):
                 raise KeyError # Path points to a file, not a directory
            return current_level
        except (KeyError, TypeError):
            return None # Invalid path or not a directory

    current_directory_content = get_dir_content(current_dir_path)
    if current_directory_content is None:
        # Should not happen if path logic is correct, but fallback
        return f"Error: Invalid current path '{current_dir_path}'", "root"

    if cmd == "pwd":
        return f"/{current_dir_path}", current_dir_path

    elif cmd == "ls":
        target_path = current_dir_path
        if args: # ls specific directory
            # Rudimentary path handling: only supports relative for now
            if args[0].startswith('/') or args[0] == '..':
                 return "ls: Absolute paths and '..' not supported in this simulation.", current_dir_path
            target_path = f"{current_dir_path}/{args[0]}".strip('/')
            target_content = get_dir_content(target_path)
            if target_content:
                return "\n".join(target_content.keys()), current_dir_path
            else:
                return f"ls: cannot access '{args[0]}': No such file or directory", current_dir_path
        else: # ls current directory
            return "\n".join(current_directory_content.keys()), current_dir_path

    elif cmd == "cat":
        if not args:
            return "Usage: cat [filename]", current_dir_path
        filename = args[0]
         # Rudimentary path handling
        if '/' in filename:
             return "cat: Paths not supported in filename.", current_dir_path

        if filename in current_directory_content:
            content = current_directory_content[filename]
            if isinstance(content, dict): # Trying to cat a directory
                 return f"cat: {filename}: Is a directory", current_dir_path
            else:
                 return str(content), current_dir_path # Return file content
        else:
            return f"cat: {filename}: No such file or directory", current_dir_path

    elif cmd == "cd":
        if not args or args[0] in ('.', '..'):
            # Simplifying: No '..' or '.' support
             return f"cd: Only changing into subdirectories is supported.", current_dir_path
        target_dir = args[0]
        if target_dir.startswith('/'): # Absolute path not supported
             return "cd: Absolute paths not supported.", current_dir_path

        new_path_str = f"{current_dir_path}/{target_dir}".strip('/')
        new_dir_content = get_dir_content(new_path_str)

        if new_dir_content is not None and isinstance(new_dir_content, dict):
            return f"Changed directory to /{new_path_str}", new_path_str # Return empty output, new path
        else:
            return f"cd: {target_dir}: No such file or directory", current_dir_path

    else:
        # Fallback for unknown commands - let adaptive response handle it
        return f"Command '{command_line}' executed (simulated).", current_dir_path


# --- SSH Honeypot Implementation ---

class HoneypotSSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        peer = conn.get_extra_info('peername')
        logging.info(f"[SSH] Connection established from {peer}")

    def connection_lost(self, exc):
        if exc:
            logging.warning(f"[SSH] Connection lost with error: {exc}")
        else:
            logging.info("[SSH] Connection lost.")

    async def begin_auth(self, username):
        # Accept any username/password for simulation, log attempt
        logging.info(f"[SSH] Authentication attempt for user '{username}'")
        return True # Always allow auth in this educational honeypot

class HoneypotSSHSession(asyncssh.SSHServerSession):
    def __init__(self, session_id):
        self.session_id = session_id
        self._buffer = ""
        self._cwd = "root" # Start in simulated /root
        self._chan = None
        super().__init__()

    def connection_made(self, chan):
        self._chan = chan
        # Simulate TCP/IP fingerprinting randomization
        ttl = random.randint(50, 128)
        window_size = random.choice([2048, 4096, 8192, 16384, 32768, random.randint(1024, 65535)])
        # Randomize banner
        banner_variation = random.choice([
            "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            "SSH-2.0-OpenSSH_6.6.1",
            "SSH-2.0-dropbear_2020.78"
        ])
        # Note: asyncssh handles the SSH handshake banner; we write after auth.
        self._chan.write(f"Welcome! [{banner_variation} simulated]\n")
        self._chan.write(f"[System Info] Logged in. (Simulated TCP: TTL={ttl} Window={window_size})\n")
        self._chan.write("Type 'help' for available commands, 'exit' to disconnect.\n")
        self._chan.write(f"[{self._cwd}] # ") # Initial prompt

    def data_received(self, data, datatype):
        self._buffer += data
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            command = line.strip()
            if command: # Ignore empty lines
                asyncio.create_task(self.handle_command(command))

    async def handle_command(self, command):
        lower_cmd = command.lower()
        response = ""
        new_cwd = self._cwd # Assume CWD doesn't change unless 'cd' is successful

        async def get_base_response():
            nonlocal response, new_cwd # Allow modification of outer scope vars
            if lower_cmd == "exit":
                response = "Goodbye!"
                self._chan.write(response + "\n")
                self._chan.exit(0)
                return response # Return needed for adaptive_response, though connection closes

            elif lower_cmd == "help":
                response = "Simulated commands: ls, cat <file>, pwd, cd <dir>, vuln-check, help, exit"
                return response

            elif lower_cmd == "vuln-check":
                vuln = config["fake_vulnerabilities"]["ssh"]
                response = f"Vulnerability detected: {vuln['cve']} - {vuln['description']}"
                return response

            elif lower_cmd.startswith(("ls", "cat", "pwd", "cd")):
                response, new_cwd = simulate_filesystem_command(command, self._cwd)
                return response
            else:
                 # Generic response for unhandled commands
                response = f"-bash: {command.split()[0]}: command not found"
                return response

        # Use adaptive response wrapper
        adaptive_msg = await adaptive_response(self.session_id, command, get_base_response)

        if self._chan.is_closing(): return # Don't write if connection is closing (e.g., after exit)

        self._chan.write(adaptive_msg + "\n")
        self._cwd = new_cwd # Update current directory if 'cd' was successful
        self._chan.write(f"[{self._cwd}] # ") # Write next prompt

    def eof_received(self):
        logging.info(f"[SSH] EOF received for session {self.session_id}")
        self._chan.exit(0)

    def session_closed(self):
        logging.info(f"[SSH] Session {self.session_id} closed.")
        # Clean up history for this session_id
        if self.session_id in command_history:
            del command_history[self.session_id]

async def start_ssh_server():
    # Ensure the host key exists, create if not
    if not os.path.exists(config["ssh_host_key_path"]):
         try:
             key = asyncssh.generate_private_key('ssh-ed25519')
             key.write_private_key(config["ssh_host_key_path"])
             logging.info(f"[SSH] Generated new host key: {config['ssh_host_key_path']}")
         except Exception as e:
             logging.error(f"[SSH] Failed to generate host key: {e}")
             return # Cannot start without a key

    try:
        await asyncssh.create_server(
            HoneypotSSHServer, '', config["ports"]["ssh"],
            server_host_keys=[config["ssh_host_key_path"]],
            process_factory=lambda proc: HoneypotSSHSession(session_id=f"ssh-{proc.get_extra_info('peername')[0]}-{time.time()}")
        )
        logging.info(f"[SSH] Server listening on port {config['ports']['ssh']}")
    except (OSError, asyncssh.Error) as exc:
        logging.error(f"[SSH] Failed to start server: {exc}")


# --- Telnet Honeypot Implementation ---

async def handle_telnet(reader, writer):
    addr = writer.get_extra_info("peername")
    session_id = get_session_id(writer)
    logging.info(f"[Telnet] Connection from {addr} ({session_id})")

    banner = random.choice([
        b"Welcome to Generic Telnet Service (Ubuntu Linux)\r\n",
        b"Login required.\r\n",
        b"RouterX Telnet Interface - Unauthorized access prohibited.\r\n"
    ])
    writer.write(banner)
    writer.write(b"Enter commands. Use 'vuln-check' for vulnerability info, or 'exit' to disconnect.\r\n")
    await writer.drain()

    while True:
        writer.write(b"> ")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=300) # 5 min timeout
        except asyncio.TimeoutError:
            logging.warning(f"[Telnet] Timeout for {addr}")
            break
        except ConnectionResetError:
             logging.warning(f"[Telnet] Connection reset by peer {addr}")
             break

        if not data:
            logging.info(f"[Telnet] Connection closed by {addr}")
            break

        command = data.decode(errors='ignore').strip()
        if not command: continue

        async def get_base_response():
            lower_cmd = command.lower()
            if lower_cmd == "exit":
                response = "Goodbye!"
                return response # Will be written before closing
            elif lower_cmd == "vuln-check":
                vuln = config["fake_vulnerabilities"]["telnet"]
                return f"Vulnerability detected: {vuln['cve']} - {vuln['description']}"
            elif lower_cmd in ["ls", "dir", "help", "status"]:
                 # Simple canned responses for common commands
                 return f"Simulated output for '{command}'."
            else:
                return f"Command '{command}' executed (simulated)."

        adaptive_msg = await adaptive_response(session_id, command, get_base_response)

        writer.write(adaptive_msg.encode() + b"\r\n")
        await writer.drain()

        if command.lower() == "exit":
            break

    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionAbortedError, ConnectionResetError) as e:
        # Log the specific error type but perhaps at a lower level or with less emphasis
        logging.debug(f"[Telnet] Graceful close failed for {addr} due to client disconnect: {e}")
    except Exception as e:
        # Log other potential closing errors more prominently
        logging.error(f"[Telnet] Unexpected error during close for {addr}: {e}")
    finally:
        logging.info(f"[Telnet] Connection from {addr} processed/closed.")
        if session_id in command_history:
            try:
                del command_history[session_id]
            except KeyError:
                pass  # Might have already been deleted if error happened earlier

async def start_telnet_server():
    try:
        server = await asyncio.start_server(handle_telnet, host='', port=config["ports"]["telnet"])
        logging.info(f"[Telnet] Server listening on port {config['ports']['telnet']}")
        async with server:
            await server.serve_forever()
    except OSError as exc:
        logging.error(f"[Telnet] Failed to start server: {exc}")

# --- FTP Honeypot Implementation ---

def start_ftp_server():
    class HoneypotFTPHandler(FTPHandler):
        def on_connect(self):
            logging.info(f"[FTP] Connection established from {self.remote_ip}")

        def on_disconnect(self):
            logging.info(f"[FTP] Connection from {self.remote_ip} closed")

        def on_login(self, username):
             logging.info(f"[FTP] Login attempt: user='{username}'")
             # Allow anonymous or simple user/pass
             pass # Authentication handled by authorizer

        def on_logout(self, username):
            logging.info(f"[FTP] Logout: user='{username}'")

        # Override RETR to check for the vulnerability trigger file
        def ftp_RETR(self, file):
            logging.info(f"[FTP] Attempt to retrieve file: '{file}' from {self.remote_ip}")
            if file.lower() == "vuln.txt":
                vuln = config["fake_vulnerabilities"]["ftp"]
                # Use respond method which handles FTP protocol details
                self.respond(f"150 Opening data connection for vuln.txt")
                # Simulate sending vulnerability info as file content
                vuln_data = f"Vulnerability Triggered!\nCVE: {vuln['cve']}\nDescription: {vuln['description']}\n".encode()
                # Send data over the data connection (assuming standard active/passive handling by pyftpdlib)
                try:
                    # This relies on the data connection being established by the library
                    # We simulate sending the data directly here for simplicity, actual transfer needs data connection
                    self.push_dtp_data(vuln_data, isproducer=False)
                    self.respond("226 Transfer complete.")
                except Exception as e:
                     logging.error(f"[FTP] Error during simulated RETR vuln.txt data transfer: {e}")
                     self.respond("451 Requested action aborted: local error in processing.")

            elif file.lower() in ["readme.txt", "welcome.txt"]:
                 self.respond(f"150 Opening data connection for {file}")
                 readme_data = b"Welcome to the Simulated FTP Server.\nThis system is for authorized use only.\n"
                 self.push_dtp_data(readme_data, isproducer=False)
                 self.respond("226 Transfer complete.")
            else:
                # Simulate "file not found" for other files
                logging.warning(f"[FTP] Denied retrieval of non-decoy file: '{file}'")
                self.respond("550 Requested action not taken. File unavailable.")


        # Log other common commands
        def ftp_LIST(self, path):
             logging.info(f"[FTP] LIST command received for path: '{path}' from {self.remote_ip}")
             # Simulate a directory listing
             listing = (
                "-rw-r--r-- 1 ftp ftp      75 Apr 15 10:00 readme.txt\n"
                "-rw-r--r-- 1 ftp ftp       0 Apr 15 10:01 vuln.txt\n" # Hint the vuln file exists
                "drwxr-xr-x 2 ftp ftp    4096 Apr 14 09:30 pub\n"
             )
             self.respond("150 Here comes the directory listing.")
             self.push_dtp_data(listing.encode(), isproducer=False)
             self.respond("226 Directory send OK.")

        def ftp_STOR(self, file):
             logging.info(f"[FTP] Attempt to store file: '{file}' from {self.remote_ip}")
             # Deny uploads in this simulation
             self.respond("553 Requested action not taken. File name not allowed (Uploads disabled).")


    authorizer = DummyAuthorizer()
    # Allow anonymous access to a fake root directory "."
    authorizer.add_anonymous(".", perm="elr") # e=cd, l=list, r=read
    # Optionally, add a fake user
    # authorizer.add_user("testuser", "password123", ".", perm="elr")

    handler = HoneypotFTPHandler
    handler.authorizer = authorizer
    handler.banner = random.choice([
        "220 ProFTPD 1.3.5 Server (Debian) [::ffff:127.0.0.1]\r\n",
        "220 vsftpd 3.0.3 ready.\r\n",
        "220 Microsoft FTP Service\r\n",
        "220 Welcome to Simple FTP Server v1.1\r\n"
    ])
    # Enable passive mode (often needed for clients behind NAT)
    handler.passive_ports = range(60000, 60010) # Use a small range of high ports

    address = ('', config["ports"]["ftp"])
    try:
        ftp_server = FTPServer(address, handler)
        logging.info(f"[FTP] Server listening on port {config['ports']['ftp']}")
        ftp_server.serve_forever() # This blocks the thread
    except OSError as exc:
         logging.error(f"[FTP] Failed to start server: {exc}")


def run_ftp_server_in_thread():
    """Runs the blocking FTP server in a separate thread."""
    ftp_thread = threading.Thread(target=start_ftp_server, daemon=True)
    ftp_thread.start()
    logging.info("[FTP] Server started in background thread.")
    return ftp_thread

# --- LDAP Honeypot Implementation ---

async def handle_ldap_interactive(reader, writer):
    addr = writer.get_extra_info("peername")
    session_id = get_session_id(writer)
    logging.info(f"[LDAP] Connection from {addr} ({session_id})")

    writer.write(b"Welcome to Simulated OpenLDAP Service\r\n")
    writer.write(b"Commands: bind, search <query>, more, vuln-check, exit\r\n")
    await writer.drain()

    stage = 0  # For multi-step 'search' -> 'more' interaction
    last_query = ""

    while True:
        writer.write(b"LDAP> ")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=300)
        except asyncio.TimeoutError:
            logging.warning(f"[LDAP] Timeout for {addr}")
            break
        except ConnectionResetError:
             logging.warning(f"[LDAP] Connection reset by peer {addr}")
             break

        if not data:
            logging.info(f"[LDAP] Connection closed by {addr}")
            break

        command = data.decode(errors='ignore').strip()
        if not command: continue

        async def get_base_response():
            nonlocal stage, last_query # Allow modification
            lower_cmd = command.lower()

            if lower_cmd == "exit":
                return "Goodbye!"
            elif lower_cmd == "bind":
                 # Could ask for DN/password here for more realism
                 return "Bind successful (simulated anonymous bind)."
            elif lower_cmd.startswith("search"):
                query = command[len("search"):].strip()
                if not query:
                    return "Usage: search <filter> (e.g., search objectClass=*)"
                else:
                    last_query = query # Store for 'more' context
                    # Simulate initial search results
                    response = f"Search results for '{query}':\r\n"
                    response += "dn: ou=Users,dc=example,dc=com\r\n"
                    response += "objectClass: organizationalUnit\r\n"
                    response += "ou: Users\r\n\r\n"
                    response += "dn: uid=admin,ou=Users,dc=example,dc=com\r\n"
                    response += "objectClass: inetOrgPerson\r\n"
                    response += "uid: admin\r\n"
                    response += "cn: Administrator\r\n"
                    response += "\r\nType 'more' for potentially more entries..."
                    stage = 1 # Set stage for 'more' command
                    return response
            elif lower_cmd == "more" and stage == 1:
                # Simulate additional results if 'more' is used after search
                response = f"Additional LDAP entries for query '{last_query}':\r\n"
                response += "dn: uid=jdoe,ou=Users,dc=example,dc=com\r\n"
                response += "objectClass: inetOrgPerson\r\n"
                response += "uid: jdoe\r\n"
                response += "cn: John Doe\r\n\r\n"
                response += "dn: uid=asmith,ou=Groups,dc=example,dc=com\r\n" # Different OU
                response += "objectClass: groupOfNames\r\n"
                response += "cn: Admins\r\n"
                stage = 0 # Reset stage
                return response
            elif lower_cmd == "more" and stage == 0:
                 return "No active search context. Use 'search' first."
            elif lower_cmd == "vuln-check":
                vuln = config["fake_vulnerabilities"]["ldap"]
                # Simulate finding vuln during a search-like action
                return f"Vulnerability detected during simulated operation: {vuln['cve']} - {vuln['description']}"
            else:
                return f"Command '{command}' processed (simulated)."

        adaptive_msg = await adaptive_response(session_id, command, get_base_response)

        writer.write(adaptive_msg.encode() + b"\r\n")
        await writer.drain()

        if command.lower() == "exit":
            break

    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionAbortedError, ConnectionResetError) as e:
        # Log the specific error type but perhaps at a lower level or with less emphasis
        logging.debug(f"[LDAP] Graceful close failed for {addr} due to client disconnect: {e}")
    except Exception as e:
        # Log other potential closing errors more prominently
        logging.error(f"[LDAP] Unexpected error during close for {addr}: {e}")
    finally:
        logging.info(f"[LDAP] Connection from {addr} processed/closed.")
        if session_id in command_history:
            try:
                del command_history[session_id]
            except KeyError:
                pass  # Might have already been deleted if error happened earlier

async def start_ldap_server():
    try:
        server = await asyncio.start_server(handle_ldap_interactive, host='', port=config["ports"]["ldap"])
        logging.info(f"[LDAP] Server listening on port {config['ports']['ldap']}")
        async with server:
            await server.serve_forever()
    except OSError as exc:
        logging.error(f"[LDAP] Failed to start server: {exc}")

# --- SMB Honeypot Implementation ---

async def handle_smb_interactive(reader, writer):
    addr = writer.get_extra_info("peername")
    session_id = get_session_id(writer)
    logging.info(f"[SMB] Connection from {addr} ({session_id})")

    writer.write(b"Welcome to Simulated SMB Service (Samba 4.x)\r\n")
    writer.write(b"Commands: list, browse <share>, connect <share>, vuln-check, exit\r\n")
    await writer.drain()

    # Predefined simulated shares with decoy file names.
    shares = {
        "PUBLIC": ["shared_doc.txt", "presentation.ppt", "project_plan.xlsx", "logo.jpg"],
        "USERDATA": ["backup_config.dat", "my_documents.zip", "important_notes.txt"],
        "ADMIN$": ["system.log", "security_policy.pdf", "user_list.csv", "patch_installer.exe"],
        "IPC$": ["(Remote IPC)"] # Special share
    }
    current_share_browse = None # Track which share is being browsed for multi-step

    while True:
        writer.write(b"SMB> ")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=300)
        except asyncio.TimeoutError:
            logging.warning(f"[SMB] Timeout for {addr}")
            break
        except ConnectionResetError:
             logging.warning(f"[SMB] Connection reset by peer {addr}")
             break

        if not data:
            logging.info(f"[SMB] Connection closed by {addr}")
            break

        command = data.decode(errors='ignore').strip()
        if not command: continue

        async def get_base_response():
            nonlocal current_share_browse
            lower_cmd = command.lower()
            parts = command.split()
            cmd_verb = parts[0].lower() if parts else ""

            if lower_cmd == "exit":
                return "Goodbye!"
            elif cmd_verb == "list":
                share_list = "\n".join([f"  {name:<10} {'Disk' if name != 'IPC$' else 'IPC'}" for name in shares.keys()])
                return f"Available shares:\r\n{share_list}"
            elif cmd_verb == "browse":
                if len(parts) < 2:
                    return "Usage: browse <share_name>"
                share_name = parts[1].upper()
                if share_name in shares:
                    current_share_browse = share_name # Set context for 'more' if we add it
                    files = shares[share_name]
                    file_listing = "\n".join([f"  - {fname}" for fname in files])
                    return f"Files in share '{share_name}':\r\n{file_listing}"
                else:
                     return f"Error: Share '{parts[1]}' not found."
            elif cmd_verb == "connect":
                if len(parts) < 2:
                    return "Usage: connect <share_name>"
                share_name = parts[1].upper()
                if share_name in shares:
                    # Simulate connecting and showing some decoy info
                     return f"Successfully connected to share '{share_name}'.\r\nHint: Use 'browse {share_name}' to see files."
                else:
                    return f"Error connecting to share '{parts[1]}': Not found or access denied."
            elif lower_cmd == "vuln-check":
                vuln = config["fake_vulnerabilities"]["smb"]
                # Simulate triggering vuln during a connection attempt or browse
                return f"Vulnerability detected during SMB operation: {vuln['cve']} - {vuln['description']}"
            else:
                # Simulate generic SMB command execution/failure
                return f"Command '{command}' executed (simulated response/error)."


        adaptive_msg = await adaptive_response(session_id, command, get_base_response)

        writer.write(adaptive_msg.encode() + b"\r\n")
        await writer.drain()

        if command.lower() == "exit":
            break

    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionAbortedError, ConnectionResetError) as e:
        # Log the specific error type but perhaps at a lower level or with less emphasis
        logging.debug(f"[SMB] Graceful close failed for {addr} due to client disconnect: {e}")
    except Exception as e:
        # Log other potential closing errors more prominently
        logging.error(f"[SMB] Unexpected error during close for {addr}: {e}")
    finally:
        logging.info(f"[SMB] Connection from {addr} processed/closed.")
        if session_id in command_history:
            try:
                del command_history[session_id]
            except KeyError:
                pass  # Might have already been deleted if error happened earlier

async def start_smb_server():
    try:
        server = await asyncio.start_server(handle_smb_interactive, host='', port=config["ports"]["smb"])
        logging.info(f"[SMB] Server listening on port {config['ports']['smb']}")
        async with server:
            await server.serve_forever()
    except OSError as exc:
        logging.error(f"[SMB] Failed to start server: {exc}")


# --- NETBIOS Honeypot Implementation ---

async def handle_netbios_interactive(reader, writer):
    addr = writer.get_extra_info("peername")
    session_id = get_session_id(writer)
    logging.info(f"[NETBIOS] Connection from {addr} ({session_id})")

    writer.write(b"Simulated NETBIOS Name Service Listener\r\n")
    writer.write(b"Commands: nbstat, name query <name>, vuln-check, exit\r\n")
    await writer.drain()

    while True:
        writer.write(b"NETBIOS> ")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=300)
        except asyncio.TimeoutError:
            logging.warning(f"[NETBIOS] Timeout for {addr}")
            break
        except ConnectionResetError:
             logging.warning(f"[NETBIOS] Connection reset by peer {addr}")
             break

        if not data:
            logging.info(f"[NETBIOS] Connection closed by {addr}")
            break

        command = data.decode(errors='ignore').strip()
        if not command: continue

        async def get_base_response():
            lower_cmd = command.lower()
            parts = command.split()
            cmd_verb = parts[0].lower() if parts else ""

            if lower_cmd == "exit":
                return "Goodbye!"
            elif cmd_verb == "nbstat":
                # Simulate nbtstat -A <ip> output
                return (
                    "Simulated NetBIOS Remote Machine Name Table\r\n"
                    "   Name               Type         Status\r\n"
                    "---------------------------------------------\r\n"
                    "   HONEYPOT-SRV    UNIQUE      Registered\r\n"
                    "   WORKGROUP       GROUP       Registered\r\n"
                    "   HONEYPOT-SRV    UNIQUE      Registered\r\n"
                    "   HONEYPOT-SRV    UNIQUE      Registered\r\n"
                    "MAC Address = 00-DE-C0-DE-00-01" # Fake MAC
                )
            elif cmd_verb == "name" and len(parts) > 2 and parts[1].lower() == "query":
                name_to_query = parts[2]
                # Simulate a lookup
                if name_to_query.upper() == "HONEYPOT-SRV":
                    return f"Name query result for '{name_to_query}': 192.168.1.100 (simulated)"
                else:
                    return f"Name query failed for '{name_to_query}': Not found (simulated)"
            elif lower_cmd == "vuln-check":
                vuln = config["fake_vulnerabilities"]["netbios"]
                return f"Vulnerability check simulated: {vuln['cve']} - {vuln['description']}"
            else:
                 return f"Command '{command}' executed (simulated NETBIOS response)."


        adaptive_msg = await adaptive_response(session_id, command, get_base_response)

        writer.write(adaptive_msg.encode() + b"\r\n")
        await writer.drain()

        if command.lower() == "exit":
            break

    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionAbortedError, ConnectionResetError) as e:
        # Log the specific error type but perhaps at a lower level or with less emphasis
        logging.debug(f"[NETBIOS] Graceful close failed for {addr} due to client disconnect: {e}")
    except Exception as e:
        # Log other potential closing errors more prominently
        logging.error(f"[NETBIOS] Unexpected error during close for {addr}: {e}")
    finally:
        logging.info(f"[NETBIOS] Connection from {addr} processed/closed.")
        if session_id in command_history:
            try:
                del command_history[session_id]
            except KeyError:
                pass  # Might have already been deleted if error happened earlier


async def start_netbios_server():
    try:
        server = await asyncio.start_server(handle_netbios_interactive, host='', port=config["ports"]["netbios"])
        logging.info(f"[NETBIOS] Server listening on port {config['ports']['netbios']}")
        async with server:
            await server.serve_forever()
    except OSError as exc:
        logging.error(f"[NETBIOS] Failed to start server: {exc}")

# --- Main Routine ---

async def main_async():
    """Runs all asynchronous servers."""
    # Create tasks for each async server
    tasks = [
        asyncio.create_task(start_ssh_server()),
        asyncio.create_task(start_telnet_server()),
        asyncio.create_task(start_ldap_server()),
        asyncio.create_task(start_smb_server()),
        asyncio.create_task(start_netbios_server()),
    ]
    logging.info("Starting all asynchronous honeypot services...")
    # Keep running until KeyboardInterrupt or error
    await asyncio.gather(*tasks)

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info("Initializing Advanced Honeypot Simulation...")

    # Start the blocking FTP server in its own thread
    ftp_thread = run_ftp_server_in_thread()

    # Run the main async loop for other services
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logging.info("Ctrl+C received. Shutting down honeypot simulation...")
    except Exception as e:
        logging.error(f"An unexpected error occurred in the main loop: {e}")
    finally:
        # Optional: Add cleanup logic here if needed
        # (e.g., wait for FTP thread to finish, though it's daemon)
        # ftp_thread.join() # Might block shutdown if FTP server hangs
        logging.info("Honeypot simulation terminated.")


if __name__ == '__main__':
    main()