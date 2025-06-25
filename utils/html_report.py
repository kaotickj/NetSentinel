from datetime import datetime
import html

def generate_html_report(scan_results: dict, output_path: str):
    """
    Generates an HTML report file from the scan results.

    scan_results dict structure:
    {
        "target": str,
        "hostname": str,
        "ports": list of dicts: {"port": int, "status": str, "banner": str},
        "smb_shares": list of strings,
        "kerberos_info": dict or None,
        "password_spray_successes": list of (username, password) tuples (optional),
        "password_spray_failures": list of (username, password) tuples (optional),
        "scan_time": datetime,
    }
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def esc(text):
        return html.escape(str(text))

    port_rows = "\n".join(
        f"<tr><td>{esc(p['port'])}</td><td>{esc(p['status'])}</td><td>{esc(p['banner'])}</td></tr>"
        for p in scan_results.get("ports", [])
    )

    smb_section = "<p>No SMB shares found or enumeration skipped.</p>"
    if scan_results.get("smb_shares"):
        shares_list = "".join(f"<li>{esc(s)}</li>" for s in scan_results["smb_shares"])
        smb_section = f"<ul>{shares_list}</ul>"

    kerberos_section = "<p>No Kerberos info available or enumeration skipped.</p>"
    if scan_results.get("kerberos_info"):
        kerberos_details = "<ul>"
        for k, v in scan_results["kerberos_info"].items():
            kerberos_details += f"<li>{esc(k)}: {esc(v)}</li>"
        kerberos_details += "</ul>"
        kerberos_section = kerberos_details

    spray_successes = scan_results.get("password_spray_successes", [])
    spray_failures = scan_results.get("password_spray_failures", [])

    if spray_successes:
        spray_success_rows = "".join(
            f"<tr><td>{esc(u)}</td><td>{esc(p)}</td></tr>" for u, p in spray_successes
        )
        spray_success_html = f"""
        <h3>Successful Password Spraying Attempts</h3>
        <table>
            <thead><tr><th>Username</th><th>Password</th></tr></thead>
            <tbody>{spray_success_rows}</tbody>
        </table>
        """
    else:
        spray_success_html = "<p>No successful password spraying attempts.</p>"

    if spray_failures:
        spray_failure_rows = "".join(
            f"<tr><td>{esc(u)}</td><td>{esc(p)}</td></tr>" for u, p in spray_failures
        )
        spray_failure_html = f"""
        <h3>Failed Password Spraying Attempts</h3>
        <details>
            <summary>{len(spray_failures)} failed credential attempts (click to expand)</summary>
            <table>
                <thead><tr><th>Username</th><th>Password</th></tr></thead>
                <tbody>{spray_failure_rows}</tbody>
            </table>
        </details>
        """
    else:
        spray_failure_html = "<p>No failed password spraying attempts recorded.</p>"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>NetSentinel Scan Report for {esc(scan_results.get('target'))}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #ccc; }}
            table {{ border-collapse: collapse; width: 90%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #666; padding: 8px; text-align: left; }}
            th {{ background-color: #333; color: #66ccff; }}
            h1, h2, h3 {{ color: #66ccff; }}
            summary {{ cursor: pointer; font-weight: bold; margin-top: 10px; }}
            details table {{ margin-top: 10px; }}
        </style>
    </head>
    <body>
        <h1>NetSentinel Scan Report</h1>
        <p><strong>Scan time:</strong> {esc(now)}</p>
        <p><strong>Target IP:</strong> {esc(scan_results.get('target'))}</p>
        <p><strong>Hostname:</strong> {esc(scan_results.get('hostname', 'N/A'))}</p>

        <h2>Open Ports</h2>
        <table>
            <thead><tr><th>Port</th><th>Status</th><th>Banner</th></tr></thead>
            <tbody>{port_rows}</tbody>
        </table>

        <h2>SMB Shares</h2>
        {smb_section}

        <h2>Kerberos Information</h2>
        {kerberos_section}

        <h2>Password Spraying Results</h2>
        {spray_success_html}
        {spray_failure_html}

    </body>
    </html>
    """

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

