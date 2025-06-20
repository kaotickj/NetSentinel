# core/smb_enum.py

from impacket.smbconnection import SMBConnection
from utils.logger import Logger
import socket

class SMBEnumerator:
    def __init__(self, logger: Logger):
        self.logger = logger

    def try_anonymous_login(self, ip):
        try:
            conn = SMBConnection(ip, ip, timeout=3)
            conn.login('', '')  # Anonymous login attempt
            shares = conn.listShares()
            share_list = []
            for share in shares:
                share_name = share['shi1_netname'][:-1]  # Trim null terminator
                share_remark = share['shi1_remark'][:-1]
                share_list.append({
                    'name': share_name,
                    'remark': share_remark
                })
                self.logger.success(f"[{ip}] Found share: {share_name} - {share_remark}")
            conn.logoff()
            return share_list
        except Exception as e:
            self.logger.debug(f"[{ip}] SMB anonymous login failed or no shares: {str(e)}")
            return None

    def enumerate(self, host_list):
        self.logger.info("Starting SMB share enumeration...")
        for host in host_list:
            ip = host.get('ip')
            self.logger.debug(f"Probing SMB on {ip}")
            shares = self.try_anonymous_login(ip)
            if shares:
                host['smb_shares'] = shares
