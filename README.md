# DragonAttacker

<p align="center">
  <img src="https://github.com/DV64/DragonAttacker/blob/master/another/logo.png" alt="DragonAttacker Logo" width="300"/>
</p>

<p align="center">
  <a href="https://github.com/DV64/DragonAttacker/stargazers"><img src="https://img.shields.io/github/stars/DV64/DragonAttacker" alt="Stars Badge"/></a>
  <a href="https://github.com/DV64/DragonAttacker/network/members"><img src="https://img.shields.io/github/forks/DV64/DragonAttacker" alt="Forks Badge"/></a>
  <a href="https://github.com/DV64/DragonAttacker/issues"><img src="https://img.shields.io/github/issues/DV64/DragonAttacker" alt="Issues Badge"/></a>
  <a href="https://github.com/DV64/DragonAttacker/blob/main/LICENSE"><img src="https://img.shields.io/github/license/DV64/DragonAttacker" alt="License Badge"/></a>
</p>

## 🌟 Overview

**DragonAttacker** is an educational network diagnostic tool designed for testing network security and resilience. It simulates various types of network traffic for authorized penetration testing and security research purposes only.

> ⚠️ **IMPORTANT LEGAL DISCLAIMER**: This tool is provided for **EDUCATIONAL PURPOSES ONLY**. Using this tool against targets without explicit permission is **ILLEGAL** and may result in criminal charges or civil liability. You are solely responsible for your actions when using this tool.

## 🔥 Features

- **Multiple Attack Vectors**: Supports UDP Flood, TCP SYN Flood, HTTP Flood, Slowloris, and ICMP Flood attacks
- **Smart Target Selection**: Intelligently chooses the most effective attack method based on the target service
- **Interactive Setup**: User-friendly terminal interface to configure attack parameters
- **Real-time Statistics**: Live monitoring of attack effectiveness with packet and data rates
- **Advanced Encryption**: Implements sophisticated crypto techniques with automatic key rotation
- **Anonymization Options**: Built-in traffic anonymization capabilities
- **Dynamic Resource Management**: Automatically manages system resources to maintain stability

## 📋 Requirements

- Python 3.7+
- Linux-based operating system (Some features require root privileges)
- Required Python packages:
  - socket
  - ssl
  - multiprocessing
  - hashlib
  - struct
  - asyncio
  - psutil (for resource monitoring)

## 🚀 Installation

1. Clone this repository:
```bash
git clone https://github.com/DV64/DragonAttacker.git
cd DragonAttacker
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## 💻 Usage

1. Run the script with Python:
```bash
python DragonAttacker.py
```

2. For full functionality (some attack methods require root privileges):
```bash
sudo python DragonAttacker.py
```

3. Follow the interactive prompts to configure your target and attack parameters.

4. Press `Ctrl+C` to stop the attack at any time.

## 📊 Attack Methods

DragonAttacker includes several sophisticated attack methods for network diagnostics:

### UDP Flood
Sends a high volume of UDP packets to the target to consume bandwidth and resources.

### TCP SYN Flood
Exploits the TCP handshake process by sending numerous SYN packets without completing the handshake.

### HTTP Flood
Sends legitimate-looking HTTP requests to web servers, mimicking normal browser behavior.

### Slowloris
Maintains many connections to the target web server by sending partial requests, eventually exhausting the server's connection pool.

### ICMP Flood
Overwhelms the target with ICMP Echo Request packets (ping flood).

## 🔒 Encryption and Security

DragonAttacker implements advanced cryptographic techniques:

- 256-bit AES encryption for payload protection
- Multiple cipher modes (CTR, CFB, OFB) with automatic rotation
- HMAC-SHA512 for message authentication
- Automatic key rotation for enhanced security

## 🛡️ Ethical Use Guidelines

When using DragonAttacker for legitimate security testing:

1. **Always obtain written permission** before testing any system
2. **Document the scope** of your testing
3. **Limit the duration** of your tests
4. **Monitor for unintended consequences**
5. **Report findings responsibly** to the system owner

## 🤝 Contributing

Contributions to improve DragonAttacker are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌐 Contact

DV64 - [@DV64_GitHub](https://github.com/DV64)

Project Link: [https://github.com/DV64/DragonAttacker](https://github.com/DV64/DragonAttacker)
