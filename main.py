# main.py

import argparse
import json
from datetime import datetime
from utils import Logger, Config, COMMON_TCP_PORTS, parse_ports, generate_html_report
from core import NetworkScanner, SMBEnumerator, KerberosScanner

def load_user_list(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def load_password_list(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def smb_password_spray(target_ip, domain, user_list, password_list, logger, delay=1):
    import time
    successes = []
    failures = []

    smb_enum = SMBEnumerator(target_ip, domain, logger)

    no_connection_fail_count = 0
    max_no_conn_failures = 3  # Threshold for early stopping

    for username in user_list:
        for password in password_list:
            if smb_enum.connection is None:
                logger.error("No SMB connection available, stopping password spray.")
                return successes, failures

            logger.debug(f"Trying {username}:{password}")
            try:
                success = smb_enum.try_login(username, password)
                if success:
                    logger.info(f"SUCCESS: {username}:{password}")
                    successes.append((username, password))
                    no_connection_fail_count = 0
                    break
                else:
                    failures.append((username, password))
                    no_connection_fail_count = 0
            except Exception as e:
                err_msg = str(e).lower()
                if "no smb connection" in err_msg or smb_enum.connection is None:
                    no_connection_fail_count += 1
                    logger.error(f"No SMB connection available for login attempts (failure count: {no_connection_fail_count})")
                    if no_connection_fail_count >= max_no_conn_failures:
                        logger.error("Repeated connection failures detected, stopping password spray early.")
                        return successes, failures
                else:
                    no_connection_fail_count = 0
                logger.warning(f"Error during login attempt for {username}:{password} - {e}")

            time.sleep(delay)

    return successes, failures

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Network Recon Tool")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
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

    target_ip = args.target
    scan_type = args.scan_type

    hostname = ""
    if args.resolve_hostnames:
        import socket
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
            logger.debug(f"Resolved {target_ip} → {hostname}")
            logger.info(f"Resolved hostname: {hostname}")
        except Exception as e:
            logger.warning(f"Reverse DNS resolution failed for {target_ip}: {e}")

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

    scanner = NetworkScanner(target_ip, logger)
    logger.info(f"Starting network scan on {target_ip}. Scan type: {scan_type}")
    results = scanner.run()

    if args.debug:
        import pprint
        logger.debug(f"Scanner raw results:\n{pprint.pformat(results)}")

    open_ports = results.get(target_ip, {}).get("open_ports", [])
    if open_ports:
        logger.info(f"Open ports on {target_ip}: {open_ports}")
    else:
        logger.warning(f"No open ports detected on {target_ip}.")

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

    scan_results = {
        "target": target_ip,
        "hostname": hostname,
        "ports": [
            {"port": p, "status": "Open", "banner": scanner.get_banner(target_ip, p)}
            for p in open_ports
        ],
        "smb_shares": smb_shares,
        "kerberos_info": kerberos_info,
        "password_spray_successes": password_spray_successes,
        "password_spray_failures": password_spray_failures,
        "scan_time": datetime.now(),
    }

    if args.html_report:
        try:
            generate_html_report(scan_results, args.html_report)
            logger.info(f"HTML report generated at {args.html_report}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

    logger.success("NetSentinel recon complete.")

if __name__ == "__main__":
    main()

