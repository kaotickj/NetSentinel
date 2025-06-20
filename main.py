import argparse
import json
from datetime import datetime

from utils import Logger, Config, COMMON_TCP_PORTS, parse_ports
from core import NetworkScanner, SMBEnumerator, KerberosScanner


def main():
    parser = argparse.ArgumentParser(
        description="NetSentinel: Covert Network Reconnaissance Framework",
        epilog="Author: KaotickJ — Red Team Reconnaissance Tool"
    )

    parser.add_argument("--target", required=True, help="Target CIDR or IP (e.g. 192.168.1.0/24 or 10.0.0.5)")
    parser.add_argument("--scan-type", choices=["stealth", "full"], default="stealth", help="Type of scan (default: stealth)")
    parser.add_argument("--resolve-hostnames", action="store_true", help="Attempt DNS resolution of IPs to hostnames")
    parser.add_argument("--ports", help="Comma-separated list of TCP ports to scan or keyword 'common'")
    parser.add_argument("--smb-enum", action="store_true", help="Enable SMB share enumeration (TCP 445/139)")
    parser.add_argument("--kerberos-scan", action="store_true", help="Enable Kerberos service enumeration (TCP/UDP 88)")
    parser.add_argument("--user-list", help="File containing usernames for AS-REP roasting checks")
    parser.add_argument("--export-json", help="Output results to specified JSON file")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")

    args = parser.parse_args()

    # Initialize logger
    logger = Logger(debug=args.debug)
    logger.banner("NetSentinel Network Recon Tool")

    # Load config (for Kerberos/LDAP auth)
    try:
        cfg = Config()
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return

    # Validate Kerberos if requested
    if args.kerberos_scan and not cfg.validate():
        logger.error("Kerberos scan requested but configuration is incomplete.")
        return

    # Parse ports to scan
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except Exception as e:
            logger.error(f"Invalid ports argument: {e}")
            return
    else:
        ports = COMMON_TCP_PORTS

    # Start recon scanning
    scanner = NetworkScanner(
        target_cidr=args.target,
        stealth=(args.scan_type == "stealth"),
        ports=ports,
        logger=logger
    )
    results = scanner.run()

    # Optional DNS resolution
    if args.resolve_hostnames:
        scanner.enrich_results()

    # SMB Enumeration
    if args.smb_enum:
        smb_enum = SMBEnumerator(logger)
        smb_enum.enumerate(results)

    # Kerberos Enumeration
    if args.kerberos_scan:
        user_list = []
        if args.user_list:
            try:
                with open(args.user_list, 'r') as f:
                    user_list = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.warning(f"Failed to load user list file '{args.user_list}': {e}")

        krb = KerberosScanner(
            logger=logger,
            domain=cfg.domain,
            username=cfg.username,
            password=cfg.password,
            dc_ip=cfg.dc_ip,
            ldap_username=cfg.ldap_username,
            ldap_password=cfg.ldap_password
        )
        kerberos_results = krb.enumerate(targets=[cfg.dc_ip], user_list=user_list)
        results['kerberos'] = kerberos_results

    # Export JSON output
    if args.export_json:
        try:
            with open(args.export_json, 'w') as f:
                json.dump(results, f, indent=2)
            logger.success(f"Results exported to {args.export_json}")
        except Exception as e:
            logger.error(f"Failed to write JSON file: {e}")

    logger.success("NetSentinel recon complete.")


if __name__ == "__main__":
    main()
