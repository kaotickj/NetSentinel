"""
Ports configuration module.

Defines common TCP ports for scanning and allows customization.
"""

COMMON_TCP_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    88,    # Kerberos
    110,   # POP3
    135,   # MS RPC
    139,   # NetBIOS
    143,   # IMAP
    161,   # SNMP
    389,   # LDAP
    443,   # HTTPS
    445,   # SMB
    636,   # LDAPS
    993,   # IMAPS
    995,   # POP3S
    1433,  # MS SQL
    1521,  # Oracle
    1723,  # PPTP
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    8080,  # HTTP Alternate
]

def parse_ports(port_string: str) -> list[int]:
    """
    Parses a comma-separated string of ports and port ranges into a list of integers.

    Args:
        port_string (str): e.g. "22,80,1000-1010"

    Returns:
        list[int]: Parsed port numbers.
    """
    ports = set()
    parts = port_string.split(',')

    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-')
                start = int(start)
                end = int(end)
                ports.update(range(start, end + 1))
            except ValueError:
                continue  # Ignore invalid parts
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue

    return sorted(ports)
