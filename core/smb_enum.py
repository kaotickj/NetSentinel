# core/smb_enum.py

import logging
from impacket.smbconnection import SMBConnection, SessionError

class SMBEnumerator:
    def __init__(self, target_ip, domain, logger=None):
        self.target_ip = target_ip
        self.domain = domain
        self.logger = logger or logging.getLogger(__name__)
        self.connection = None

        # Try to establish initial anonymous connection
        try:
            self.connection = SMBConnection(self.target_ip, self.target_ip, sess_port=445, timeout=10)
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
                shares.append(share['shi1_netname'].decode('utf-8').rstrip('\x00'))
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
        if not self.connection:
            self.logger.error("No SMB connection available for login attempts")
            return False

        try:
            self.connection.logoff()
        except Exception:
            pass  # ignore errors on logoff

        try:
            # Create a new SMB connection per login attempt
            conn = SMBConnection(self.target_ip, self.target_ip, sess_port=445, timeout=10)
            conn.login(username, password, domain=self.domain)
            self.logger.debug(f"SMB login succeeded for {username}@{self.domain}")
            conn.logoff()
            return True
        except SessionError as e:
            self.logger.debug(f"SMB login failed for {username}@{self.domain}: {e}")
            return False
        except Exception as e:
            self.logger.warning(f"Error during SMB login attempt for {username}@{self.domain}: {e}")
            return False

