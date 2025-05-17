import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from beez_scanner.software_detector import get_installed_packages
from beez_scanner.cpe_matcher import match_packages_to_cves

installed = get_installed_packages()
matches = match_packages_to_cves(installed)

print(f"🛡️ Found {len(matches)} possible vulnerable packages:\n")
for match in matches[:10]:
    print(f"{match['cve_id']} | CVSS: {match['cvss_v3']} | CPE: {match['cpe']}")
    print(f"↳ {match['description']}\n")
