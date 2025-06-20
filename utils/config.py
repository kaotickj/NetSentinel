# utils/config.py

import os
from utils.logger import Logger

class Config:
    def __init__(self):
        # You may optionally load from environment or a secrets file here
        self.domain = os.getenv('NETSENTINEL_DOMAIN') or "corp.local"
        self.username = os.getenv('NETSENTINEL_USER') or "lowpriv"
        self.password = os.getenv('NETSENTINEL_PASS') or "Spring2025!"
        self.dc_ip = os.getenv('NETSENTINEL_DC') or "10.0.0.5"

    def validate(self):
        if not all([self.domain, self.username, self.password, self.dc_ip]):
            Logger.error("Configuration incomplete. Please set all required fields.")
            return False
        return True

    def dump(self):
        Logger.info("Current Configuration:")
        Logger.info(f"  Domain:    {self.domain}")
        Logger.info(f"  Username:  {self.username}")
        Logger.info(f"  Password:  {'*' * len(self.password)}")
        Logger.info(f"  DC IP:     {self.dc_ip}")
