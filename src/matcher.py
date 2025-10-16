import json

def load_inventory(inventory_path):
    with open(inventory_path, "r", encoding="utf-8") as f:
        return json.load(f)

def match_cves_to_inventory(cve_entries, inventory_path):
    """
    Matches each CVE entry to the inventory based on product name.
    Returns a list of dicts: {asset, cves:[...]}
    """
    inventory = load_inventory(inventory_path)
    inventory_products = [item.get("name") for item in inventory]

    matched_results = []

    for entry in cve_entries:
        asset = entry.get("asset", "N/A")
        cves = entry.get("cves", [])
        matched_cves = []

        for cve in cves:
            product = cve.get("product", "")
            if any(inv.lower() in product.lower() for inv in inventory_products) or asset in inventory_products:
                matched_cves.append(cve)
            else:
                matched_cves.append(cve)  # Keep all, optional filter

        matched_results.append({"asset": asset, "cves": matched_cves})

    return matched_results
