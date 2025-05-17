import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from beez_scanner.windows_patch_checker import is_cve_patched

# Replace this with a real CVE from Microsoft's CVE-to-KB map
cve_id = "CVE-2023-28252"

result = is_cve_patched(cve_id)
print(f"🔍 Patched status for {cve_id}: {result}")
