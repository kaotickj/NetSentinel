# core/kerberos_enum.py

import socket
import threading
from queue import Queue
from typing import Dict, List, Optional, Union
import logging
import random
import datetime

from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AS_REQ,
    AS_REP,
    KDC_REQ_BODY,
    PrincipalName,
)
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.der.decoder import decode as der_decode

from ldap3 import Server, Connection, ALL, NTLM


class KerberosScanner:
    KERBEROS_TCP_PORT = 88
    KERBEROS_UDP_PORT = 88

    def __init__(
        self,
        logger: logging.Logger,
        domain: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        dc_ip: Optional[str] = None,
        max_threads: int = 10,
        timeout: int = 3,
        ldap_username: Optional[str] = None,
        ldap_password: Optional[str] = None,
    ):
        """
        Initialize KerberosScanner with options for Kerberos and LDAP enumeration.

        Args:
            logger: Logger instance.
            domain: Target domain.
            username, password: Credentials for Kerberos auth.
            dc_ip: Domain Controller IP address.
            max_threads: Max concurrent threads.
            timeout: Socket timeout seconds.
            ldap_username, ldap_password: Credentials for LDAP connection.
        """
        self.logger = logger
        self.domain = domain.upper()
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.max_threads = max_threads
        self.timeout = timeout
        self.ldap_username = ldap_username
        self.ldap_password = ldap_password

        self.results: Dict[str, Dict] = {}
        self.lock = threading.Lock()

    def enumerate(self, targets: Optional[List[str]] = None, user_list: Optional[List[str]] = None) -> Dict[str, Dict]:
        """
        Main enumeration entry.

        Args:
            targets: List of IP addresses to scan for Kerberos.
            user_list: List of usernames for targeted user enumeration.

        Returns:
            Dictionary of results.
        """
        if targets is None:
            if not self.dc_ip:
                self.logger.error("No targets specified and no domain controller IP configured.")
                return {}
            targets = [self.dc_ip]

        self.logger.info(f"Starting Kerberos enumeration on {len(targets)} hosts.")

        queue = Queue()
        for ip in targets:
            queue.put(ip)

        def worker():
            while not queue.empty():
                ip = queue.get()
                try:
                    self._scan_host(ip, user_list=user_list)
                except Exception as e:
                    self.logger.error(f"Unhandled exception scanning {ip}: {e}")
                finally:
                    queue.task_done()

        thread_count = min(self.max_threads, len(targets))
        threads = []
        for _ in range(thread_count):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        queue.join()
        self.logger.info("Kerberos enumeration complete.")
        return self.results

    def _scan_host(self, ip: str, user_list: Optional[List[str]] = None):
        host_result = {
            'kerberos_tcp_88_open': False,
            'kerberos_udp_88_open': False,
            'can_request_as_req': False,
            'as_rep_roastable_users': [],
            'kerberoastable_spns': [],
            'ldap_enumeration': {},
            'error': None,
        }

        # TCP port check
        if self._tcp_port_open(ip, self.KERBEROS_TCP_PORT):
            host_result['kerberos_tcp_88_open'] = True
            self.logger.debug(f"{ip}: TCP port 88 is open.")
        else:
            self.logger.debug(f"{ip}: TCP port 88 is closed or filtered.")
            with self.lock:
                self.results[ip] = host_result
            return

        # UDP port check (optional)
        if self._udp_port_open(ip, self.KERBEROS_UDP_PORT):
            host_result['kerberos_udp_88_open'] = True

        # AS-REQ ticket request test (if credentials supplied)
        if self.username and self.password:
            try:
                can_request = self._attempt_kerberos_as_req(ip)
                host_result['can_request_as_req'] = can_request
            except Exception as e:
                self.logger.warning(f"{ip}: AS-REQ attempt failed: {e}")

            # AS-REP Roasting detection
            if user_list:
                roastable = self._detect_as_rep_roast(ip, user_list)
                host_result['as_rep_roastable_users'] = roastable

            # Kerberoasting (SPN enumeration + TGS requests)
            spns = self._kerberoast(ip)
            host_result['kerberoastable_spns'] = spns

        # LDAP Enumeration (optional, requires ldap_username/password)
        if self.ldap_username and self.ldap_password:
            try:
                ldap_data = self._ldap_enumerate(ip)
                host_result['ldap_enumeration'] = ldap_data
            except Exception as e:
                self.logger.warning(f"{ip}: LDAP enumeration failed: {e}")

        with self.lock:
            self.results[ip] = host_result

    def _tcp_port_open(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except Exception:
            return False

    def _udp_port_open(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b'\x00', (ip, port))
            sock.recvfrom(1024)
            sock.close()
            return True
        except Exception:
            return False

    def _attempt_kerberos_as_req(self, ip: str) -> bool:
        """
        Attempt AS-REQ using the new Impacket API.
        Returns True if ticket obtained, else False.
        """
        try:
            username = self.username
            password = self.password
            domain = self.domain
            kdc_ip = ip
            timeout = self.timeout

            # Build PrincipalName
            principal = Principal()
            principal.nameType = constants.PrincipalNameType.NT_PRINCIPAL.value
            principal.components = [username.encode('utf-8')]

            # Build AS_REQ and KDC_REQ_BODY
            as_req = AS_REQ()
            as_req['pvno'] = 5
            as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

            kdc_req_body = KDC_REQ_BODY()
            kdc_req_body['kdc-options'] = constants.KDCOptions()
            kdc_req_body['kdc-options'][0] = 1  # forwardable
            kdc_req_body['kdc-options'][1] = 1  # renewable

            # Set the client name and realm
            kdc_req_body['cname'] = PrincipalName()
            kdc_req_body['cname']['name-type'] = principal.nameType
            kdc_req_body['cname']['name-string'] = [username]

            kdc_req_body['realm'] = domain

            # Set server principal (krbtgt)
            kdc_req_body['sname'] = PrincipalName()
            kdc_req_body['sname']['name-type'] = constants.PrincipalNameType.NT_SRV_INST.value
            kdc_req_body['sname']['name-string'] = ['krbtgt', domain]

            # Set requested encryption types (e.g., AES256, AES128)
            kdc_req_body['etype'] = [int(constants.EncryptionType.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionType.aes128_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionType.rc4_hmac.value)]

            # Set time fields
            now = datetime.datetime.utcnow()
            kdc_req_body['from'] = KerberosTime.to_asn1(now)
            kdc_req_body['till'] = KerberosTime.to_asn1(now + datetime.timedelta(hours=10))
            kdc_req_body['rtime'] = KerberosTime.to_asn1(now + datetime.timedelta(hours=10))

            # Set nonce
            kdc_req_body['nonce'] = random.getrandbits(31)

            # No addresses
            kdc_req_body['addresses'] = None

            as_req['req-body'] = kdc_req_body

            # Encode request
            message = der_encode(as_req)

            # Send request and receive response
            response = sendReceive(message, kdc_ip, timeout=timeout)

            # Decode response
            rep = der_decode(response, asn1Spec=AS_REP())[0]

            # If decode succeeds, return True
            return True

        except KerberosError as e:
            self.logger.debug(f"AS-REQ failed: {e}")
            return False

        except Exception as e:
            self.logger.debug(f"Exception in AS-REQ: {e}")
            return False

    def _detect_as_rep_roast(self, ip: str, users: List[str]) -> List[str]:
        """
        Detect AS-REP roastable users (users with 'Do not require pre-authentication' flag).

        Args:
            ip: KDC IP
            users: List of usernames to test.

        Returns:
            List of usernames vulnerable to AS-REP roasting.
        """
        roastable_users = []

        for user in users:
            try:
                # Build AS-REQ without pre-auth for this user
                principal = Principal()
                principal.nameType = constants.PrincipalNameType.NT_PRINCIPAL.value
                principal.components = [user.encode('utf-8')]

                as_req = AS_REQ()
                as_req['pvno'] = 5
                as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

                kdc_req_body = KDC_REQ_BODY()
                kdc_req_body['kdc-options'] = constants.KDCOptions()
                kdc_req_body['kdc-options'][0] = 1  # forwardable
                kdc_req_body['kdc-options'][1] = 1  # renewable

                kdc_req_body['cname'] = PrincipalName()
                kdc_req_body['cname']['name-type'] = principal.nameType
                kdc_req_body['cname']['name-string'] = [user]

                kdc_req_body['realm'] = self.domain

                kdc_req_body['sname'] = PrincipalName()
                kdc_req_body['sname']['name-type'] = constants.PrincipalNameType.NT_SRV_INST.value
                kdc_req_body['sname']['name-string'] = ['krbtgt', self.domain]

                kdc_req_body['etype'] = [int(constants.EncryptionType.aes256_cts_hmac_sha1_96.value),
                                        int(constants.EncryptionType.aes128_cts_hmac_sha1_96.value),
                                        int(constants.EncryptionType.rc4_hmac.value)]

                now = datetime.datetime.utcnow()
                kdc_req_body['from'] = KerberosTime.to_asn1(now)
                kdc_req_body['till'] = KerberosTime.to_asn1(now + datetime.timedelta(hours=10))
                kdc_req_body['rtime'] = KerberosTime.to_asn1(now + datetime.timedelta(hours=10))

                kdc_req_body['nonce'] = random.getrandbits(31)

                kdc_req_body['addresses'] = None

                as_req['req-body'] = kdc_req_body

                message = der_encode(as_req)

                # Send request and get response
                sendReceive(message, ip, timeout=self.timeout)

            except KerberosError as e:
                # Error code KDC_ERR_PREAUTH_REQUIRED == 24
                if hasattr(e, 'error_code') and e.error_code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                    # User requires pre-auth, so skip
                    continue
                else:
                    # No pre-auth required - vulnerable user
                    roastable_users.append(user)

            except Exception:
                # Other errors, treat user as vulnerable (conservative)
                roastable_users.append(user)

        return roastable_users

    def _kerberoast(self, ip: str) -> List[Dict[str, Union[str, int]]]:
        """
        Kerberoastable SPN enumeration: enumerate SPNs and request TGS tickets.

        NOTE: This simplified version only enumerates SPNs via LDAP.
        Requesting TGS tickets would require full TGS-REQ construction.

        Returns:
            List of dicts containing 'spn' and 'username'.
        """
        self.logger.debug(f"Kerberoast enumeration placeholder called for {ip}.")
        if not (self.ldap_username and self.ldap_password):
            self.logger.debug("LDAP credentials not provided; skipping SPN enumeration.")
            return []

        try:
            ldap_data = self._ldap_enumerate(ip)
            spns = ldap_data.get('spns', [])
            # Return as list of dicts with 'spn' key only, since TGS-REQ not implemented
            return [{'spn': spn} for spn in spns]
        except Exception as e:
            self.logger.warning(f"{ip}: Kerberoast LDAP enumeration failed: {e}")
            return []

    def _ldap_enumerate(self, ip: str) -> Dict:
        """
        Perform LDAP queries against the DC to enumerate users, groups, SPNs.

        Requires ldap3 library and valid credentials.

        Returns:
            Dict with keys: 'users', 'groups', 'spns' each mapping to lists.
        """
        server = Server(ip, get_info=ALL, connect_timeout=self.timeout)
        user = f"{self.ldap_username}@{self.domain}" if '@' not in self.ldap_username else self.ldap_username
        conn = Connection(server, user=user, password=self.ldap_password, authentication=NTLM, auto_bind=True)

        base_dn = ','.join([f"DC={part}" for part in self.domain.split('.')])

        results = {
            'users': [],
            'groups': [],
            'spns': [],
        }

        # Enumerate users
        conn.search(search_base=base_dn,
                    search_filter='(&(objectClass=user)(objectCategory=person))',
                    attributes=['sAMAccountName', 'userPrincipalName'])
        for entry in conn.entries:
            results['users'].append(str(entry.sAMAccountName))

        # Enumerate groups
        conn.search(search_base=base_dn,
                    search_filter='(objectClass=group)',
                    attributes=['cn'])
        for entry in conn.entries:
            results['groups'].append(str(entry.cn))

        # Enumerate SPNs (servicePrincipalName attribute)
        conn.search(search_base=base_dn,
                    search_filter='(servicePrincipalName=*)',
                    attributes=['servicePrincipalName'])
        for entry in conn.entries:
            spns = entry.servicePrincipalName.values if hasattr(entry.servicePrincipalName, 'values') else []
            results['spns'].extend(spns)

        conn.unbind()
        return results

