import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from beez_scanner.redhat_patch_checker import is_cve_patched

# Replace with real CVE and package on your system
cve_id = "CVE-2023-0464"
package = "openssl"

result = is_cve_patched(cve_id, package)
print(f"🔍 Patched status for {cve_id} in {package}: {result}")
