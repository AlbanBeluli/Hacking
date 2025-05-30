# Hacking Stuff

This repository contains a collection of commands for reconnaissance and playful hacking-related activities. Use these responsibly and only on systems you have explicit permission to test. This `README.md` serves as a quick reference for security enthusiasts and learners.

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

Install tools using your package manager (e.g., `apt`, `brew`) or follow official documentation. Wordlists like `dirbuster` and `seclists` are required for `gobuster`.

---

## Ethical Use

These commands are for educational purposes and authorized security testing only. Unauthorized use on systems you don’t own or have explicit permission to test is illegal and unethical. Always obtain written consent before performing any scans or tests.

---

## Recon Stuff

Commands for gathering information about a target domain or system.

```bash
curl -i domain.com
whois domain.com
whatweb domain.com
rustscan -a domain.com
sudo nmap -sS -sV -T4 domain.com -oN nmap_domain.txt

urlfinder -d domain.com -o domain.txt
nikto -h domain.com
amass enum -d domain.com
gobuster dir -u domain.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u domain.com -w /usr/share/seclists/sublist3r -d domain.com

tshark -Y 'http.request.method == "GET"' -i eth0

wpscan --url domain.com --enumerate u
wpscan --url domain.com --enumerate vp,vt --plugins-detection

theHarvester -d domain.com -b all

nc -lvnp 1234

sudo chmod +s /bin/bash
bash -p
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

---

**Note**: Replace `domain.com` with the target domain and ensure you have authorization. Some commands require root privileges or specific tools installed. Save outputs to files (e.g., `nmap -oN output.txt`) for easier analysis.
