# DragonAttacker

**DragonAttacker** is a tool designed to simulate Distributed Denial of Service (DDoS) attacks. It can send a large volume of UDP packets to a target, potentially causing network disruption. This tool is for educational purposes only, and should **never** be used to attack any network or website without explicit permission.

---

### ⚠️ Important Note
- **Do not use** this tool on unauthorized systems or networks. Unauthorized DDoS attacks are illegal and unethical.
- Attacks launched from **Windows** systems are not recommended, as they are generally ineffective in this context.

---

## Installation Instructions

### Linux Installation

To install and run DragonAttacker on a Linux system, follow these steps:

1. Open your terminal and clone the repository:
   ```bash
   git clone https://github.com/DV64/DragonAttacker
   ```

2. Change to the project directory:
   ```bash
   cd DragonAttacker
   ```

3. Run the script using Python:
   ```bash
   python3 DragonAttacker.py
   ```

   If `python3` is not available, you can try:
   ```bash
   python DragonAttacker.py
   ```

### Termux Installation (Android)

To install DragonAttacker on **Termux** (a terminal emulator for Android), follow these steps:

1. Update and upgrade your packages:
   ```bash
   apt update && apt upgrade
   ```

2. Install the required packages:
   ```bash
   apt install git python
   ```

3. Clone the repository:
   ```bash
   git clone https://github.com/DV64/DragonAttacker
   ```

4. Change to the project directory:
   ```bash
   cd DragonAttacker
   ```

5. Run the script:
   ```bash
   python3 DragonAttacker.py
   ```

---

### Usage

Once the script is running, you'll be prompted to provide the following:
1. **Target IP or Host**: The IP address or domain name of the target.
2. **Port**: The port to send packets to (default: 80).
3. **Duration**: The duration of the attack in seconds.

---

### Example Command:

```bash
[*] IP or Host Target: 192.168.1.1
[*] Port [Default port 80]: 80
[*] Duration of the Attack (in seconds): 60
```

---

### Disclaimer

This tool is intended **only** for educational purposes and testing in controlled environments (such as your own systems or networks where you have explicit permission). **Never** use this tool to target websites or networks without proper authorization. Misuse of this tool can result in serious legal consequences. Always follow ethical and legal guidelines when using network testing tools.
