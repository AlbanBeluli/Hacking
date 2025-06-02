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
# SNMP Enumeration
snmpwalk -v2c -c public domain.com
# Packet Capture
tcpdump -i eth0 -w capture.pcap
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

### Host Recon
- `whoami`, `hostname`, `ipconfig /all`, `ifconfig`, `ps aux`, `tasklist`, `netstat -ano`

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
- Triage: Identify high-value targets first
- Timebox: Don't get stuck—move on and return later
- Document as you go

---

## 8. PT1 Exam Cheatsheet & Checklist

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
