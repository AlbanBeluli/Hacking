# Hacking Stuff

This repository contains a collection of commands for reconnaissance, networking utilities, Linux hacking techniques, password cracking, and playful activities. Use these responsibly and only on systems you have explicit permission to test. This `README.md` serves as a quick reference for security enthusiasts and learners.

---

## Prerequisites

Ensure the following tools are installed before running the commands:

- **RustScan**: Fast port scanner (`rustscan`)
- **Nikto**: Web server scanner (`nikto`)
- **Amass**: Subdomain enumeration tool (`amass`)
- **Gobuster**: Directory and subdomain brute-forcer (`gobuster`)
- **WPScan**: WordPress vulnerability scanner (`wpscan`)
- **hping3**: Packet crafting tool (`hping3`)
- **tshark**: Network protocol analyzer (`tshark`)
- **nmap**: Network exploration tool (`nmap`)
- **theHarvester**: OSINT tool for emails and subdomains (`theHarvester`)
- **curl**, **whois**, **whatweb**, **netcat**: Common utilities
- **dig**, **nslookup**, **host**, **ifconfig**, **ip**, **netstat**, **ss**, **mtr**, **iftop**, **ethtool**, **scp**, **sftp**, **rsync**, **bmon**, **vnstat**, **nmcli**: Additional networking tools
- **ffuf**, **dnsenum**, **subfinder**, **sqlmap**: Additional recon tools
- **assetfinder**, **dnsx**, **anubis**, **sherlock**, **spiderfoot**, **metagoofil**, **linkedin2username**, **h8mail**, **dnstwist**, **altdns**, **findomain**, **asnlookup**, **masscan**, **naabu**, **massdns**, **fierce**, **dnsvalidator**, **puredns**, **shuffledns**, **hosthunter**, **dirsearch**, **gospider**, **hakrawler**, **httprobe**, **httpx**, **paramspider**, **arjun**, **linkfinder**, **403bypasser**, **nuclei**, **wapiti**, **dalfox**, **xsstrike**, **jaeles**, **burpsuite**, **owasp zap**, **sslscan**, **waybackurls**, **gau**, **katana**, **gowitness**: Additional recon tools
- **John the Ripper**: Password cracking tool (`john`)
- **Hashcat**: Advanced password recovery tool (`hashcat`)

Install tools using your package manager (e.g., `apt`, `brew`) or follow official documentation. Wordlists like `dirbuster`, `seclists`, and `rockyou.txt` are required for tools like `gobuster`, `john`, and `hashcat`.

---

## Ethical Use

These commands are for educational purposes and authorized security testing only. Unauthorized use on systems you don’t own or have explicit permission to test is illegal and unethical. Always obtain written consent before performing any scans or tests.

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
rustscan -a domain.com  # Fast port scanning
masscan -p1-65535 domain.com  # Mass IP port scanning
naabu -host domain.com  # Enumerate valid ports for hosts
nc -zv domain.com 80  # Scan specific ports using netcat
tshark -Y 'http.request.method == "GET"' -i eth0  # Analyze network traffic, capture packets
```

### Web Recon (Target Web Applications)

Finally, focus on web applications to discover directories, parameters, endpoints, and vulnerabilities. These tools are specific to web targets.

```bash
python3 -m http.server
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
tracepath domain.com  # Similar to traceroute but doesn’t require root privileges
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

## Fun Stuff

Miscellaneous commands for playful or experimental purposes.

```bash
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

---

**Note**: Replace `domain.com` with the target domain and ensure you have authorization. Some commands require root privileges or specific tools installed. Save outputs to files (e.g., `nmap -oN output.txt`) for easier analysis.