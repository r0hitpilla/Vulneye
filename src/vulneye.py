import argparse
import json
from .nvd_fetcher import fetch_recent_cves
from .cisa_fetcher import fetch_recent_kevs
from .matcher import match_cves_to_inventory
from .report_generator import generate_html_report

def load_assets(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    parser = argparse.ArgumentParser(description="VulnEye CLI")
    parser.add_argument("--inventory", required=True, help="Path to inventory JSON")
    parser.add_argument("--output", required=True, help="Path to output HTML report")
    args = parser.parse_args()

    assets = load_assets(args.inventory)
    all_results = []

    # Fetch NVD CVEs for each asset
    for asset in assets:
        name = asset.get("name")
        version = asset.get("version")
        asset_str = f"{name} {version}" if version else name
        nvd_cves = fetch_recent_cves(asset_str)
        all_results.append({"asset": asset_str, "cves": nvd_cves})

    # Fetch KEVs from CISA and merge
    kev_cves = fetch_recent_kevs()
    for kev in kev_cves:
        all_results.append({"asset": kev.get("product", "KEV"), "cves": [kev]})

    # Match CVEs to inventory
    matches = match_cves_to_inventory(all_results, args.inventory)

    # Generate HTML report
    generate_html_report(matches, args.output)
    print(f"Report generated at {args.output}")

if __name__ == "__main__":
    main()
