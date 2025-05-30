# Hacking Stuff

This repository contains a collection of commands for reconnaissance, networking utilities, Linux hacking techniques, and playful activities. Use these responsibly and only on systems you have explicit permission to test. This `README.md` serves as a quick reference for security enthusiasts and learners.

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

Install tools using your package manager (e.g., `apt`, `brew`) or follow official documentation. Wordlists like `dirbuster` and `seclists` are required for `gobuster`.

---

## Ethical Use

These commands are for educational purposes and authorized security testing only. Unauthorized use on systems you don’t own or have explicit permission to test is illegal and unethical. Always obtain written consent before performing any scans or tests.

---

## Recon Stuff

Commands for gathering information about a target domain or system.

```bash
curl -i domain.com
whois domain.com  # Display website registration and owner information
whatweb domain.com
dig domain.com  # Query DNS related info such as A, CNAME, MX records
nslookup domain.com  # Query DNS servers interactively, also used for RR
host domain.com  # Display domain name for given IP or vice-versa, also performs DNS lookups
dnsenum domain.com  # Advanced DNS enumeration for subdomains and records
subfinder -d domain.com  # Fast subdomain enumeration, complements Amass
sudo nmap -sS -sV -T4 domain.com  # Explore and audit hosts, IPs, ports, services
rustscan -a domain.com
urlfinder -d domain.com -o domain.txt
nikto -h domain.com
amass enum -d domain.com
gobuster dir -u domain.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u domain.com -w /usr/share/seclists/sublist3r -d domain.com
ffuf -u http://domain.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  # Fast web fuzzing for directories/parameters
sqlmap -u "http://domain.com/index.php?id=1" --dbs  # Test for SQL injection (with permission)
tshark -Y 'http.request.method == "GET"' -i eth0  # Analyze network traffic, capture packets
wpscan --url domain.com --enumerate u
wpscan --url domain.com --enumerate vp,vt --plugins-detection
theHarvester -d domain.com -b all
nc -lvnp 1234  # Listen on port for TCP/UDP connections
sudo chmod +s /bin/bash
bash -p
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

Explore these resources for further learning and tool documentation:

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Kali Linux Tools Listing](https://www.kali.org/tools/)
- [SecLists GitHub](https://github.com/danielmiessler/SecLists) for wordlists
- [HackTricks](https://book.hacktricks.xyz/) for pentesting tutorials

---

**Note**: Replace `domain.com` with the target domain and ensure you have authorization. Some commands require root privileges or specific tools installed. Save outputs to files (e.g., `nmap -oN output.txt`) for easier analysis.