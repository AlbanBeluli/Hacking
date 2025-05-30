# Hacking Stuff

This document outlines various commands for reconnaissance and fun hacking-related activities. Use responsibly and only on systems you have permission to test.

---

## Recon Stuff

Commands for gathering information about a target domain or system.

```bash
rustscan -a domain.com
urlfinder -d domain.com -o domain.txt
nikto -h domain.com
amass enum -d domain.com
curl -i domain.com
whois domain.com
whatweb domain.com
sudo nmap -sS -sV -T4 domain.com
gobuster dir -u domain.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u domain.com -w /usr/share/seclists/sublist3r -d domain.com
tshark -Y 'http.request.method == "GET"' -i eth0
wpscan --url domain.com --enumerate u
wpscan --url domain.com --enumerate vp,vt --plugins-detection
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
```

---

**Note**: Replace `domain.com` with the target domain and ensure you have authorization to perform these actions. Some commands require root privileges or specific tools installed.