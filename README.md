# Advanced Interactive Honeypot Simulation

## Overview

This Python script creates an advanced, multi-service honeypot designed for educational purposes, particularly in ethical hacking and cybersecurity training environments. It simulates various network services (SSH, Telnet, FTP, LDAP, SMB, NETBIOS) with interactive shells, decoy data, adaptive responses, and simulated vulnerabilities to provide a realistic target for learning scanning, enumeration, and basic interaction techniques without exposing real systems.

## Features

* **Multiple Simulated Services:**
    * SSH (Port 2222)
    * Telnet (Port 2323)
    * FTP (Port 2121)
    * LDAP (Port 1389)
    * SMB (Port 1445)
    * NETBIOS (Port 1137)
* **Interactive Shells:** Provides basic command-line interaction for text-based protocols (SSH, Telnet, LDAP, SMB, NETBIOS).
* **Decoy Data & Filesystem:**
    * SSH simulates a basic Linux-like filesystem with `ls`, `cat`, `cd`, `pwd` commands and decoy files (e.g., `credentials.txt`, `system.conf`).
    * SMB simulates share listings (`list`, `browse`) with decoy shares and filenames.
    * FTP allows listing decoy files like `readme.txt` and `vuln.txt`.
* **Adaptive Responses:** Command responses on text-based services include slight delays and notes (e.g., `[note: Processing...]`) if the same command is repeated frequently within a session, simulating basic defensive awareness.
* **Simulated Vulnerabilities:** Each service has a fake vulnerability entry triggered by a specific action:
    * `vuln-check` command in SSH, Telnet, LDAP, SMB, NETBIOS.
    * Retrieving the file `vuln.txt` via `RETR` command in FTP.
* **Basic Fingerprint Evasion:** Randomizes banners and simulates varying TCP parameters (TTL, Window Size) for SSH connections to make fingerprinting slightly less reliable.
* **Configurable:** Ports and vulnerability details can be easily modified in the `config` dictionary within the script.
* **Logging:** Logs connection attempts, authentication, commands (where applicable), and errors to the console.
* **Concurrency:** Uses `asyncio` for efficient handling of multiple connections and `threading` for the blocking FTP server library.

## Installation

1.  **Prerequisites:**
    * Python 3.7 or higher is recommended.
    * `pip` (Python package installer).

2.  **Get the Script:**
    * Download or clone the `advanced_honeypot.py` script to your local machine.

3.  **Install Dependencies:**
    * Navigate to the directory containing the script in your terminal.
    * Install the required Python libraries:
        ```bash
        pip install asyncssh pyftpdlib
        ```

## Configuration

* **Ports & Vulnerabilities:** You can modify the listening ports and the details of the simulated vulnerabilities by editing the `config` dictionary near the top of the `advanced_honeypot.py` file.
* **SSH Host Key:** The script will automatically generate an SSH host key file named `ssh_host_key` in the same directory upon first run if it doesn't exist.

## Running the Honeypot

1.  **Execute the Script:**
    * Open your terminal, navigate to the script's directory, and run:
        ```bash
        python advanced_honeypot.py
        ```
    * *Note:* The default ports are above 1024, so root/administrator privileges are typically *not* required. If you configure ports below 1024, you might need to run the script with `sudo` (Linux/macOS) or as Administrator (Windows).

2.  **Expected Output:**
    * You should see log messages indicating that each service is starting and listening on its configured port, similar to this:
        ```
        INFO:root:Initializing Advanced Honeypot Simulation...
        INFO:root:[FTP] Server started in background thread.
        INFO:root:Starting all asynchronous honeypot services...
        INFO:root:[SSH] Generated new host key: ssh_host_key
        INFO:root:[SSH] Server listening on port 2222
        INFO:root:[Telnet] Server listening on port 2323
        INFO:root:[LDAP] Server listening on port 1389
        INFO:root:[SMB] Server listening on port 1445
        INFO:root:[NETBIOS] Server listening on port 1137
        ```

3.  **Stopping the Honeypot:**
    * Press `Ctrl+C` in the terminal where the script is running. You should see shutdown messages.

## Interacting with the Honeypot

Use standard client tools to connect to the simulated services running on the machine where the script is executed (e.g., `localhost` or the machine's IP address). Remember to specify the correct **non-default ports**.

* **SSH (Port 2222):**
    ```bash
    ssh <username>@localhost -p 2222
    # (Password is not checked, any password will work)
    # Try commands: ls, pwd, cd etc, cat readme.txt, vuln-check
    ```

* **Telnet (Port 2323):**
    ```bash
    telnet localhost 2323
    # Try commands: help, status, vuln-check, exit
    ```

* **FTP (Port 2121):**
    ```bash
    ftp localhost 2121
    # Login as 'anonymous' (or any other username, password doesn't matter)
    # Try commands: ls, dir, get readme.txt, get vuln.txt, quit
    ```
    *Note: FTP passive mode is enabled.*

* **LDAP (Port 1389):**
    * Using `ldapsearch` (if available):
        ```bash
        # Basic anonymous search (might vary based on ldapsearch version)
        ldapsearch -x -h localhost -p 1389 -b "dc=example,dc=com" "(objectClass=*)"

        # Or connect interactively (less common with standard tools)
        # You can use netcat/telnet for basic command simulation:
        telnet localhost 1389
        # Try commands: bind, search objectClass=*, more, vuln-check, exit
        ```

* **SMB (Port 1445):**
    * Using `smbclient` (Linux/macOS, if installed):
        ```bash
        # List shares anonymously
        smbclient -L //localhost -p 1445 -N
        # (Use -U% for anonymous in some versions)

        # Or connect interactively (using netcat/telnet for basic commands):
        telnet localhost 1445
        # Try commands: list, browse PUBLIC, connect ADMIN$, vuln-check, exit
        ```
    * *Note:* Real SMB clients expect a complex protocol. Interaction via basic TCP clients like telnet/netcat will only work for the simple custom commands implemented (`list`, `browse`, `connect`, `vuln-check`, `exit`).

* **NETBIOS (Port 1137):**
    * Like SMB, real clients are complex. Use netcat/telnet for the simulated commands:
        ```bash
        telnet localhost 1137
        # Try commands: nbstat, name query HONEYPOT-SRV, vuln-check, exit
        ```

* **Scanning Tools:** Tools like `nmap` can be used to scan the ports:
    ```bash
    nmap -p 2121,2222,2323,1389,1445,1137 -sV localhost
    ```

## Disclaimer

This script is intended strictly for educational and research purposes in controlled environments. **Do not deploy this honeypot on live, production networks or use it for any malicious activities.** Unauthorized scanning or interaction with systems is illegal and unethical. The creator assumes no liability for misuse of this script. Always ensure you have explicit permission before interacting with any system, including honeypots.