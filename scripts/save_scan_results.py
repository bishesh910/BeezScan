import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
from datetime import datetime
from beez_scanner.software_detector import get_installed_packages
from beez_scanner.cpe_matcher import match_packages_to_cves


def save_results_to_json(results, output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{now}.json"
    filepath = os.path.join(output_dir, filename)

    data = {
        "scanned_at": datetime.now().isoformat(),
        "total_packages": len(get_installed_packages()),
        "total_vulnerabilities": len(results),
        "vulnerabilities": results
    }

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

    print(f"✅ Scan results saved to {filepath}")

if __name__ == "__main__":
    pkgs = get_installed_packages()
    results = match_packages_to_cves(pkgs)
    save_results_to_json(results)
