from datetime import datetime
import html

def format_kerberos_info(kerberos_info: dict) -> str:
    """
    Format Kerberos info dict into a readable HTML table.
    """
    if not kerberos_info:
        return "<p>No Kerberos info available or enumeration skipped.</p>"

    rows = []
    for key, val in kerberos_info.items():
        # Format values based on type for readability
        if isinstance(val, bool):
            display_val = "Yes" if val else "No"
        elif isinstance(val, list):
            if val:
                display_val = "<br>".join(html.escape(str(x)) for x in val)
            else:
                display_val = "<i>None</i>"
        elif isinstance(val, dict):
            if val:
                # Show key: value pairs in dict on separate lines
                display_val = "<br>".join(f"{html.escape(str(k))}: {html.escape(str(v))}" for k, v in val.items())
            else:
                display_val = "<i>None</i>"
        elif val is None:
            display_val = "<i>None</i>"
        else:
            display_val = html.escape(str(val))

        rows.append(f"<tr><td>{html.escape(key.replace('_', ' ').capitalize())}</td><td>{display_val}</td></tr>")

    return f"""
    <table>
        <thead><tr><th>Host</th><th>Result</th></tr></thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """

def generate_html_report(scan_results: dict, output_path: str):
    """
    Generates an HTML report file from the scan results.

    scan_results dict structure:
    {
        "target": str,
        "network_range": str,        # e.g. "192.168.0.0/24" (optional)
        "host_count": int,           # number of hosts scanned (optional)
        "scan_duration": str,        # human-readable duration (optional)
        "scan_time": datetime or ISO string,
        "scan_end_time": datetime or ISO string,     # new
        "full_results": {
            "10.0.0.1": {
                "target": str,
                "hostname": str,
                "ports": list of dicts: {"port": int, "status": str, "banner": str},
                "smb_shares": list of strings,
                "kerberos_info": dict or None,
                "password_spray_successes": list of (username, password),
                "password_spray_failures": list of (username, password),
                "scan_time": ISO string,
                "host_scan_start": ISO string,       # new
                "host_scan_end": ISO string,         # new
                "host_scan_duration": str,           # new
            },
            ...
        },
        "empty_hosts": list of IPs with no open ports   # new
    }
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    esc = lambda t: html.escape(str(t))

    target = esc(scan_results.get("target", ""))
    network_range = esc(scan_results.get("network_range", target))
    host_count = esc(scan_results.get("host_count", 1))
    scan_duration = esc(scan_results.get("scan_duration", "N/A"))
    scan_time = esc(scan_results.get("scan_time", now))
    scan_end_time = esc(scan_results.get("scan_end_time", "N/A"))
    full_results = scan_results.get("full_results", {})
    empty_hosts = scan_results.get("empty_hosts", [])

    host_sections = ""

    # Generate sections for hosts with open ports only
    for ip, data in full_results.items():
        hostname = esc(data.get("hostname", "N/A"))
        ports = data.get("ports", [])
        smb_shares = data.get("smb_shares", [])
        kerberos_info = data.get("kerberos_info", {})
        spray_successes = data.get("password_spray_successes", [])
        spray_failures = data.get("password_spray_failures", [])

        host_scan_start = esc(data.get("host_scan_start", "N/A"))
        host_scan_end = esc(data.get("host_scan_end", "N/A"))
        host_scan_duration = esc(data.get("host_scan_duration", "N/A"))

        port_rows = "\n".join(
            f"<tr><td>{esc(p['port'])}</td><td>{esc(p['status'])}</td><td>{esc(p['banner'])}</td></tr>"
            for p in ports
        ) or "<tr><td colspan='3'>No open ports found.</td></tr>"

        smb_html = "<p>No SMB shares found or enumeration skipped.</p>"
        if smb_shares:
            smb_html = "<ul>" + "".join(f"<li>{esc(s)}</li>" for s in smb_shares) + "</ul>"

        kerberos_html = format_kerberos_info(kerberos_info)

        spray_success_html = "<p>No successful password spraying attempts.</p>"
        if spray_successes:
            spray_success_html = f"""
            <table>
                <thead><tr><th>Username</th><th>Password</th></tr></thead>
                <tbody>{"".join(f"<tr><td>{esc(u)}</td><td>{esc(p)}</td></tr>" for u, p in spray_successes)}</tbody>
            </table>
            """

        spray_failure_html = "<p>No failed password spraying attempts recorded.</p>"
        if spray_failures:
            spray_failure_html = f"""
            <details>
                <summary>{len(spray_failures)} failed attempts (click to expand)</summary>
                <table>
                    <thead><tr><th>Username</th><th>Password</th></tr></thead>
                    <tbody>{"".join(f"<tr><td>{esc(u)}</td><td>{esc(p)}</td></tr>" for u, p in spray_failures)}</tbody>
                </table>
            </details>
            """

        host_sections += f"""
        <details>
            <summary><strong>{ip}</strong> — {len(ports)} port(s) open (click to expand)</summary>
            <h3>Hostname: {hostname}</h3>
            <p><em>Scan started:</em> {host_scan_start} | <em>Scan ended:</em> {host_scan_end} | <em>Duration:</em> {host_scan_duration}</p>

            <h4>Open Ports</h4>
            <table>
                <thead><tr><th>Port</th><th>Status</th><th>Banner</th></tr></thead>
                <tbody>{port_rows}</tbody>
            </table>

            <h4>SMB Shares</h4>
            {smb_html}

            <h4>Kerberos Info</h4>
            {kerberos_html}

            <h4>Password Spray - Successes</h4>
            {spray_success_html}

            <h4>Password Spray - Failures</h4>
            {spray_failure_html}
        </details>
        """

    empty_hosts_summary = ""
    if empty_hosts:
        empty_hosts_summary = f"<p><strong>{len(empty_hosts)}</strong> host(s) with 0 open ports.</p>"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>NetSentinel Scan Report - {network_range}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #ccc; }}
            table {{ border-collapse: collapse; width: 90%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #666; padding: 8px; text-align: left; }}
            th {{ background-color: #333; color: #66ccff; }}
            h1, h2, h3, h4 {{ color: #66ccff; }}
            summary {{ cursor: pointer; font-weight: bold; margin-top: 10px; }}
            details {{ margin-bottom: 20px; border: 1px solid #444; padding: 10px; background-color: #2a2a2a; }}
            footer {{ font-size: 0.9em; color: #888; margin-top: 30px; }}
        </style>
    </head>
    <body>
        <h1>NetSentinel Scan Report</h1>
        <p><strong>Scan started:</strong> {scan_time}</p>
        <p><strong>Scan ended:</strong> {scan_end_time}</p>
        <p><strong>Network Range:</strong> {network_range}</p>
        <p><strong>Hosts Scanned:</strong> {host_count}</p>
        <p><strong>Scan Duration:</strong> {scan_duration}</p>

        {empty_hosts_summary}

        <h2>Scan Results Per Host</h2>
        {host_sections}

        <hr>
        <footer>
            <p>Report generated on {now}</p>
        </footer>
    </body>
    </html>
    """

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

