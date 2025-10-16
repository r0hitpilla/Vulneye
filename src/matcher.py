import json

def load_inventory(path):
    with open(path) as f:
        return json.load(f)

def match_cves_to_inventory(cve_items, inventory_path):
    inventory = load_inventory(inventory_path)
    matches = []
    for cve in cve_items:
        cve_desc = ''
        if isinstance(cve, dict) and 'cve' in cve:
            cve_desc = cve['cve']['description']['description_data'][0]['value']
        else:
            cve_desc = str(cve)
        for asset in inventory.get('assets', []):
            if asset['name'].lower() in cve_desc.lower():
                matches.append({'asset': asset, 'cve': cve})
    return matches
