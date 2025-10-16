from datetime import datetime

def generate_html_report(matched_results, output_file):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    html = f"""
    <html>
    <head><title>Vulnerability Report - {now}</title></head>
    <body>
    <h1>Vulnerability Report - {now}</h1>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr>
            <th>Asset</th>
            <th>CVE</th>
            <th>Vendor</th>
            <th>Product</th>
            <th>Description</th>
            <th>CVSS</th>
            <th>Risk Level</th>
        </tr>
    """

    for entry in matched_results:
        asset = entry.get("asset", "N/A")
        for cve in entry.get("cves", []):
            cve_id = cve.get("cve_id", "N/A")
            vendor = cve.get("vendor", "N/A")
            product = cve.get("product", "N/A")
            description = cve.get("description", "N/A")
            cvss = cve.get("cvss", "N/A")

            # Determine risk level
            try:
                score = float(cvss)
                if score >= 9:
                    risk = "Critical"
                elif score >= 7:
                    risk = "High"
                elif score >= 4:
                    risk = "Medium"
                else:
                    risk = "Low"
            except:
                risk = "Medium"  # Default for KEVs or missing CVSS

            html += f"""
            <tr>
                <td>{asset}</td>
                <td>{cve_id}</td>
                <td>{vendor}</td>
                <td>{product}</td>
                <td>{description}</td>
                <td>{cvss}</td>
                <td>{risk}</td>
            </tr>
            """

    html += "</table></body></html>"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
