import pandas as pd
from nvd__fetcher import fetch_cves
from utils import get_assets, calculate_risk

# Step 1: Read all assets dynamically
assets = get_assets("assets/")

# Step 2: Fetch CVEs for each asset
all_data = []
for asset in assets:
    cves = fetch_cves(asset)
    if not cves:
        all_data.append({
            "asset": asset,
            "cve": "N/A",
            "vendor": "N/A",
            "product": "N/A",
            "vuln_name": "N/A",
            "date_added": "N/A",
            "description": "N/A",
            "cvss": "N/A"
        })
    else:
        for cve in cves:
            all_data.append({
                "asset": asset,
                "cve": cve.get("cve_id", "N/A"),
                "vendor": cve.get("vendor", "N/A"),
                "product": cve.get("product", "N/A"),
                "vuln_name": cve.get("vuln_name", "N/A"),
                "date_added": cve.get("date_added", "N/A"),
                "description": cve.get("description", "N/A"),
                "cvss": cve.get("cvss", "N/A")
            })

# Step 3: Convert to DataFrame
df = pd.DataFrame(all_data)

# Step 4: Merge multiple CVEs per asset
merged_df = df.groupby('asset').agg({
    'cve': lambda x: ', '.join(sorted(set(x))),
    'vendor': lambda x: ', '.join(sorted(set([v for v in x if v != "N/A"]))) or "N/A",
    'product': lambda x: ', '.join(sorted(set([p for p in x if p != "N/A"]))) or "N/A",
    'vuln_name': lambda x: ', '.join(sorted(set([v for v in x if v != "N/A"]))) or "N/A",
    'date_added': lambda x: ', '.join(sorted(set([d for d in x if d != "N/A"]))) or "N/A",
    'description': lambda x: ' '.join([d for d in x if d != "N/A"]),
    'cvss': lambda x: ', '.join([str(v) for v in x if v != "N/A"]) or "N/A"
}).reset_index()

# Step 5: Add management fields
merged_df['Remediation Status'] = "Pending"
merged_df['Remediation Deadline'] = "2025-10-20"
merged_df['Risk Level'] = merged_df['cvss'].apply(lambda x: calculate_risk(x.split(',')[0] if ',' in x else x))

# Step 6: Generate Markdown table
def df_to_markdown(df):
    md = '| ' + ' | '.join(df.columns) + ' |\n'
    md += '| ' + ' | '.join(['---']*len(df.columns)) + ' |\n'
    for _, row in df.iterrows():
        md += '| ' + ' | '.join(str(row[col]) for col in df.columns) + ' |\n'
    return md

markdown_report = df_to_markdown(merged_df)

# Save report
with open("vulnerability_report.md", "w") as f:
    f.write(markdown_report)

print("Vulnerability report generated: vulnerability_report.md")
import pandas as pd
from nvd__fetcher import fetch_cves
from utils import get_assets, calculate_risk

# Step 1: Dynamic asset reading
assets = get_assets("assets/")

# Step 2: Fetch CVEs
all_data = []
for asset in assets:
    cves = fetch_cves(asset)
    if not cves:
        all_data.append({
            "asset": asset,
            "cve": "N/A",
            "vendor": "N/A",
            "product": "N/A",
            "vuln_name": "N/A",
            "date_added": "N/A",
            "description": "N/A",
            "cvss": "N/A"
        })
    else:
        for cve in cves:
            all_data.append({
                "asset": asset,
                "cve": cve.get("cve_id", "N/A"),
                "vendor": cve.get("vendor", "N/A"),
                "product": cve.get("product", "N/A"),
                "vuln_name": cve.get("vuln_name", "N/A"),
                "date_added": cve.get("date_added", "N/A"),
                "description": cve.get("description", "N/A"),
                "cvss": cve.get("cvss", "N/A")
            })

# Step 3: Convert to DataFrame and merge CVEs
df = pd.DataFrame(all_data)
merged_df = df.groupby('asset').agg({
    'cve': lambda x: ', '.join(sorted(set(x))),
    'vendor': lambda x: ', '.join(sorted(set([v for v in x if v != "N/A"]))) or "N/A",
    'product': lambda x: ', '.join(sorted(set([p for p in x if p != "N/A"]))) or "N/A",
    'vuln_name': lambda x: ', '.join(sorted(set([v for v in x if v != "N/A"]))) or "N/A",
    'date_added': lambda x: ', '.join(sorted(set([d for d in x if d != "N/A"]))) or "N/A",
    'description': lambda x: ' '.join([d for d in x if d != "N/A"]),
    'cvss': lambda x: ', '.join([str(v) for v in x if v != "N/A"]) or "N/A"
}).reset_index()

# Step 4: Add management fields and risk
merged_df['Remediation Status'] = "Pending"
merged_df['Remediation Deadline'] = "2025-10-20"
merged_df['Risk Level'] = merged_df['cvss'].apply(lambda x: calculate_risk(x.split(',')[0] if ',' in x else x))

# Step 5: Sort by CVSS descending
def cvss_sort_value(cvss_str):
    try:
        return float(cvss_str.split(',')[0])
    except:
        return 0
merged_df = merged_df.sort_values(by='cvss', key=lambda x: x.map(cvss_sort_value), ascending=False)

# Step 6: Markdown report with critical/high highlight
def df_to_markdown(df):
    md = '| ' + ' | '.join(df.columns) + ' |\n'
    md += '| ' + ' | '.join(['---']*len(df.columns)) + ' |\n'
    for _, row in df.iterrows():
        row_values = []
        for col in df.columns:
            value = str(row[col])
            if col == "Risk Level" and value in ["Critical", "High"]:
                value = f"**{value}**"  # highlight
            row_values.append(value)
        md += '| ' + ' | '.join(row_values) + ' |\n'
    return md

markdown_report = df_to_markdown(merged_df)

# Step 7: Save report
with open("vulnerability_report.md", "w") as f:
    f.write(markdown_report)

print("Vulnerability report generated: vulnerability_report.md")
import pandas as pd
from nvd__fetcher import fetch_cves
from utils import get_assets, calculate_risk

# Step 1: Dynamic asset reading
assets = get_assets("assets/")

# Step 2: Fetch CVEs
all_data = []
for asset in assets:
    cves = fetch_cves(asset)
    if not cves:
        all_data.append({
            "asset": asset,
            "cve": "N/A",
            "vendor": "N/A",
            "product": "N/A",
            "vuln_name": "N/A",
            "date_added": "N/A",
            "description": "N/A",
            "cvss": "N/A"
        })
    else:
        for cve in cves:
            all_data.append({
                "asset": asset,
                "cve": cve.get("cve_id", "N/A"),
                "vendor": cve.get("vendor", "N/A"),
                "product": cve.get("product", "N/A"),
                "vuln_name": cve.get("vuln_name", "N/A"),
                "date_added": cve.get("date_added", "N/A"),
                "description": cve.get("description", "N/A"),
                "cvss": cve.get("cvss", "N/A")
            })

# Step 3: Convert to DataFrame and merge CVEs
df = pd.DataFrame(all_data)
merged_df = df.groupby('asset').agg({
    'cve': lambda x: ', '.join(sorted(set(x))),
    'vendor': lambda x: ', '.join(sorted(set([v for v in x if v != "N/A"]))) or "N/A",
    'product': lambda x: ', '.join(sorted(set([p for p in x if p != "N/A"]))) or "N/A",
    'vuln_name': lambda x: ', '.join(sorted(set([v for v in x if v != "N/A"]))) or "N/A",
    'date_added': lambda x: ', '.join(sorted(set([d for d in x if d != "N/A"]))) or "N/A",
    'description': lambda x: ' '.join([d for d in x if d != "N/A"]),
    'cvss': lambda x: ', '.join([str(v) for v in x if v != "N/A"]) or "N/A"
}).reset_index()

# Step 4: Add management fields and risk
merged_df['Remediation Status'] = "Pending"
merged_df['Remediation Deadline'] = "2025-10-20"
merged_df['Risk Level'] = merged_df['cvss'].apply(lambda x: calculate_risk(x.split(',')[0] if ',' in x else x))

# Step 5: Sort by CVSS descending
def cvss_sort_value(cvss_str):
    try:
        return float(cvss_str.split(',')[0])
    except:
        return 0
merged_df = merged_df.sort_values(by='cvss', key=lambda x: x.map(cvss_sort_value), ascending=False)

# Step 6: Markdown report with critical/high highlight
def df_to_markdown(df):
    md = '| ' + ' | '.join(df.columns) + ' |\n'
    md += '| ' + ' | '.join(['---']*len(df.columns)) + ' |\n'
    for _, row in df.iterrows():
        row_values = []
        for col in df.columns:
            value = str(row[col])
            if col == "Risk Level" and value in ["Critical", "High"]:
                value = f"**{value}**"  # highlight
            row_values.append(value)
        md += '| ' + ' | '.join(row_values) + ' |\n'
    return md

markdown_report = df_to_markdown(merged_df)

# Step 7: Save report
with open("vulnerability_report.md", "w") as f:
    f.write(markdown_report)

print("Vulnerability report generated: vulnerability_report.md")
