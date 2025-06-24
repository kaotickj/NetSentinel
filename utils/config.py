# utils/config.py

import os
import json
import socket
from utils.logger import Logger

logger = Logger()  # Create a Logger instance

class Config:
    def __init__(self, config_path='config.json'):
        config_data = {}

        # Try environment variables first
        self.domain = os.getenv('NETSENTINEL_DOMAIN')
        self.username = os.getenv('NETSENTINEL_USER')
        self.password = os.getenv('NETSENTINEL_PASS')
        self.dc_ip = os.getenv('NETSENTINEL_DC')
        self.ldap_username = os.getenv('NETSENTINEL_LDAP_USER')
        self.ldap_password = os.getenv('NETSENTINEL_LDAP_PASS')

        # If any required value is missing, try to load from config file
        if not all([self.domain, self.username, self.password, self.dc_ip]):
            try:
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load config from {config_path}: {e}")

            self.domain = self.domain or config_data.get('domain', 'corp.local')
            self.username = self.username or config_data.get('username', 'lowpriv')
            self.password = self.password or config_data.get('password', 'Spring2025!')
            self.dc_ip = self.dc_ip or config_data.get('dc_ip', '10.0.0.5')
            self.ldap_username = self.ldap_username or config_data.get('ldap_username', self.username)
            self.ldap_password = self.ldap_password or config_data.get('ldap_password', self.password)

    def validate(self):
        required = [
            self.domain, self.username, self.password, self.dc_ip,
            self.ldap_username, self.ldap_password
        ]
        if not all(required):
            logger.error("Configuration incomplete. Please set all required fields.")
            return False
        return True

    def dump(self):
        logger.info("Current Configuration:")
        logger.info(f"  Domain:         {self.domain}")
        logger.info(f"  Username:       {self.username}")
        logger.info(f"  Password:       {'*' * len(self.password)}")
        logger.info(f"  DC IP:          {self.dc_ip}")
        logger.info(f"  LDAP Username:  {self.ldap_username}")
        logger.info(f"  LDAP Password:  {'*' * len(self.ldap_password)}")

    def is_kerberos_target_reachable(self):
        try:
            with socket.create_connection((self.dc_ip, 88), timeout=3):
                return True
        except Exception:
            return False

