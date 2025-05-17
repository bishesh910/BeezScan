import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from beez_scanner.ubuntu_patch_checker import is_cve_patched

cve_id = "CVE-2023-0464"
package = "openssl"
installed_version = "3.0.2-0ubuntu1.11"

patched = is_cve_patched(cve_id, package, installed_version)
print(f"🔍 Patched status for {cve_id} in {package} {installed_version}: {patched}")
