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

def send_packets(sock, payloads, ip, port, duration, start_time, stats):
    """
    Send packets to the target until duration expires.
    Args:
        sock: The socket object.
        payloads: The payload to send.
        ip: Target IP address.
        port: Target port.
        duration: Duration of the test in seconds.
        start_time: The start time of the test.
        stats: A dictionary to store statistics.
    """
    while time.time() - start_time < duration:
        try:
            sock.sendto(payloads, (ip, port))
            stats['total_requests'] += 1
            stats['successful_requests'] += 1
        except socket.error as e:
            stats['failed_requests'] += 1
            logging.error(f"Socket error: {e}")
            break
        except Exception as e:
            stats['failed_requests'] += 1
            logging.error(f"Unexpected error: {e}")
            break

def load_test(ip, port, duration, rate_limit):
    """
    Perform a load test on the target server.
    Args:
        ip: Target IP address.
        port: Target port.
        duration: Duration of the test in seconds.
        rate_limit: Maximum requests per second.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payloads = random._urandom(1024)

    clear_console()
    logging.info(f"Starting load test on {ip}:{port} for {duration} seconds with rate limit {rate_limit} req/s.")

    stats = {
        'total_requests': 0,
        'successful_requests': 0,
        'failed_requests': 0
    }

    threads = []
    start_time = time.time()
    interval = 1 / rate_limit  # Time between requests based on rate limit

    while time.time() - start_time < duration:
        t = threading.Thread(target=send_packets, args=(sock, payloads, ip, port, duration, start_time, stats))
        threads.append(t)
        t.start()
        time.sleep(interval)  # Enforce rate limit

    for t in threads:
        t.join()

    # Display test results
    logging.info("Load test completed.")
    logging.info(f"Total Requests Sent: {stats['total_requests']}")
    logging.info(f"Successful Requests: {stats['successful_requests']}")
    logging.info(f"Failed Requests: {stats['failed_requests']}")

def main():
    """Handle user input and initiate the load test."""
    try:
        clear_console()
        print(COLORS["yellow"] + "=== Load Testing Tool ===" + COLORS["white"])
        print(COLORS["red"] + "WARNING: Use this tool only with explicit permission from the target server owner." + COLORS["white"])
        consent = input(COLORS["yellow"] + "[*] Do you have permission to test the target server? (yes/no): " + COLORS["white"]).strip().lower()
        if consent != "yes":
            logging.error("You must have explicit permission to use this tool. Exiting.")
            sys.exit()

        ip = input(COLORS["yellow"] + "[*] Enter IP or Host Target: " + COLORS["white"]).strip()
        port = input(COLORS["yellow"] + "[*] Enter Port [Default: 80]: " + COLORS["white"]).strip()
        port = int(port) if port else 80
        duration = int(input(COLORS["red"] + "[*] Enter Duration (seconds): " + COLORS["white"]).strip())
        rate_limit = int(input(COLORS["red"] + "[*] Enter Rate Limit (requests per second): " + COLORS["white"]).strip())

        if duration <= 0 or rate_limit <= 0:
            logging.error("Duration and rate limit must be positive integers.")
            sys.exit()

        load_test(ip, port, duration, rate_limit)

    except ValueError:
        logging.error("Invalid input. Please enter valid data.")
    except KeyboardInterrupt:
        logging.info("Program interrupted by user.")
        sys.exit()

if __name__ == "__main__":
    main()
