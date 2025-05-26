# Hacking Stuff

------------------------------------------------------- 
                      # RECON STUFF
------------------------------------------------------- 

rustscan -a domain.com

nikto -h domain.com

amass enum -d domain.com

curl -i domain.com
whois domain.com
whatweb domain.com

nmap -sV domain.com
nmap -O domain.com
nmap -sL domain.com
nmap --script vuln domain.com
nmap --script malware domain.com
nmap -A domain.com
nmap -D RND:10 domain.com

gobuster dir -u domain.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

gobuster dir -u domain.com -w /usr/share/seclists/

sublist3r -d domain.com


tshark -Y'http.request.method == "GET" -i eth0


wpscan --url domain.com --enumerate u
wpscan --url domain.com --enumerate vp,vt --plugins-detection


sudo chmod +s /bin/bash
bash -p




------------------------------------------------------- 
                      # FUN STUFF
------------------------------------------------------- 

ping -s 1300 -f domain.com

hping3 -S -V --flood domain.com

hping3 --traceroute -V -1 domain.com

cat /dev/urandom
alias ls="cat /dev/urandom"


