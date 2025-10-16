import argparse
from nvd_fetcher import fetch_recent_cves
from cisa_fetcher import fetch_cisa_kevs
from matcher import match_cves_to_inventory
from report_generator import generate_html_report

def main():
    parser = argparse.ArgumentParser(description='VulnEye - Automated CVE Tracker')
    parser.add_argument('--inventory', required=True, help='Path to asset inventory JSON')
    parser.add_argument('--output', required=True, help='Path to output HTML report')
    args = parser.parse_args()

    nvd_cves = fetch_recent_cves()
    kev = fetch_cisa_kevs()
    matches = match_cves_to_inventory(nvd_cves + kev, args.inventory)
    generate_html_report(matches, args.output)
    print(f'[*] Report written to {args.output}')

if __name__ == '__main__':
    main()
