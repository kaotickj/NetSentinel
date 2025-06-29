# core/recon.py

import socket
import threading
from queue import Queue
from ipaddress import ip_network
from typing import List, Dict, Union

class NetworkScanner:
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 161,
        389, 443, 445, 636, 993, 995, 1433, 1521, 1723, 3306,
        3389, 5432, 5900, 8080
    ]

    def __init__(
        self,
        target_cidr: str,
        stealth: bool = True,
        logger=None,
        max_threads: int = 50,
        ports: List[int] = None,
        port_timeout: float = 1.0,
    ):
        self.target_cidr = target_cidr
        self.stealth = stealth
        self.logger = logger
        self.max_threads = max_threads
        self.ports = ports if ports is not None else self.COMMON_PORTS
        self.port_timeout = port_timeout

        self.hosts = self._expand_targets()
        self.results: Dict[str, Dict[str, Union[str, dict, None]]] = {}
        self.lock = threading.Lock()

    def _expand_targets(self) -> List[str]:
        try:
            network = ip_network(self.target_cidr, strict=False)
            if network.num_addresses > 2:
                return [str(ip) for ip in network.hosts()]
            else:
                return [str(ip) for ip in network]
        except ValueError as e:
            if self.logger:
                self.logger.error(f"Invalid target CIDR/IP '{self.target_cidr}': {e}")
            else:
                print(f"[ERROR] Invalid target CIDR/IP '{self.target_cidr}': {e}")
            return []

    def run(self) -> Dict[str, Dict[str, Union[str, dict, None]]]:
        if not self.hosts:
            if self.logger:
                self.logger.error("No valid hosts to scan.")
            return {}

        if self.logger:
            self.logger.info(f"Starting network scan on {len(self.hosts)} hosts. Stealth mode: {self.stealth}")

        queue = Queue()
        for host in self.hosts:
            queue.put(host)

        def worker():
            while not queue.empty():
                ip = queue.get()
                try:
                    self._scan_host(ip)
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Unexpected error scanning {ip}: {e}")
                    else:
                        print(f"[ERROR] Unexpected error scanning {ip}: {e}")
                finally:
                    queue.task_done()

        thread_count = min(self.max_threads, len(self.hosts))
        threads = []
        for _ in range(thread_count):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        queue.join()

        if self.logger:
            self.logger.info("Network scan complete.")
        return self.results

    def _scan_host(self, ip: str):
        host_result = {
            'reachable': False,
            'hostname': None,
            'open_ports': {},
            'error': None,
        }

        # Ping test
        reachable = self._ping(ip)
        host_result['reachable'] = reachable
        if self.logger:
            if reachable:
                self.logger.debug(f"{ip} is reachable.")
            else:
                self.logger.debug(f"{ip} is not reachable.")

        # Reverse DNS resolution (initial)
        hostname = self._resolve_hostname(ip)
        if hostname:
            host_result['hostname'] = hostname
            if self.logger:
                self.logger.debug(f"Resolved {ip} → {hostname}")

        # If stealth is False or reachable, scan ports
        if not self.stealth or reachable:
            open_ports = self._scan_ports(ip)
            host_result['open_ports'] = open_ports

        with self.lock:
            self.results[ip] = host_result

    def enrich_results(self):
        if self.logger:
            self.logger.info("Starting reverse DNS resolution on scanned hosts...")

        for ip, data in self.results.items():
            # Only try to resolve if hostname missing or empty
            if 'hostname' not in data or not data['hostname']:
                try:
                    hostname = self._resolve_hostname(ip)
                    if hostname:
                        data['hostname'] = hostname
                        if self.logger:
                            self.logger.info(f"{ip} resolves to {hostname}")
                    else:
                        if self.logger:
                            self.logger.info(f"No PTR record found for {ip}")
                except Exception as e:
                    if self.logger:
                        self.logger.warning(f"Failed to resolve hostname for {ip}: {e}")

        if self.logger:
            self.logger.info("Reverse DNS resolution complete.")

    def _ping(self, ip: str, timeout: int = 1) -> bool:
        import platform
        import subprocess

        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout_value = str(timeout * 1000) if platform.system().lower() == 'windows' else str(timeout)

        command = ['ping', param, '1', timeout_param, timeout_value, ip]

        try:
            output = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return output.returncode == 0
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Ping failed for {ip}: {e}")
            return False

    def _resolve_hostname(self, ip: str) -> Union[str, None]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror as e:
            if self.logger:
                self.logger.debug(f"Reverse DNS failed for {ip}: {e}")
            return None

    def _scan_ports(self, ip: str) -> Dict[int, dict]:
        open_ports = {}

        for port in self.ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.port_timeout)
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner = self._grab_banner(sock)
                    open_ports[port] = {
                        'state': 'open',
                        'banner': banner
                    }
                    if self.logger:
                        self.logger.debug(f"{ip}:{port} is open; banner: {banner}")
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Exception scanning {ip}:{port} - {e}")
            finally:
                sock.close()

        return open_ports

    def _grab_banner(self, sock: socket.socket) -> str:
        banner = ''
        try:
            sock.settimeout(1.0)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except Exception:
            pass
        return banner

    def get_banner(self, ip: str, port: int) -> str:
        if ip in self.results:
            open_ports = self.results[ip].get("open_ports", {})
            if port in open_ports:
                return open_ports[port].get("banner", "")
        return ""

