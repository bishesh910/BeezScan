import requests
import distro
from packaging import version

UBUNTU_CVE_BASE = "https://people.canonical.com/~ubuntu-security/cve/pkg"

def get_ubuntu_series():
    """
    Returns Ubuntu codename, e.g., jammy for 22.04, noble for 24.04
    """
    try:
        return distro.lsb_release_info().get("codename", "")
    except Exception:
        return ""


# Global cache
_pkg_cve_cache = {}

def fetch_package_cve_data(pkg: str) -> dict:
    if pkg in _pkg_cve_cache:
        return _pkg_cve_cache[pkg]
    try:
        url = f"{UBUNTU_CVE_BASE}/{pkg}.json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            _pkg_cve_cache[pkg] = resp.json()
            return _pkg_cve_cache[pkg]
    except Exception:
        pass
    _pkg_cve_cache[pkg] = {}
    print(f"📦 Fetching Ubuntu CVEs for: {pkg}")
    return {}

def is_cve_patched(cve_id: str, package: str, installed_version: str) -> bool | None:
    series = get_ubuntu_series()
    cve_id = cve_id.upper()
    data = fetch_package_cve_data(package)
    
    if not data or cve_id not in data:
        return None

    cve_info = data[cve_id]
    pkg_status = cve_info.get("pkgs", {}).get(series, {})
    status = pkg_status.get("status")
    fixed_ver = pkg_status.get("fixed_version")

    # Can't determine status
    if status is None:
        return None

    if status.lower() == "released" and fixed_ver:
        try:
            return version.parse(installed_version) >= version.parse(fixed_ver)
        except:
            return None

    if status.lower() in ("not-affected", "ignored"):
        return True
    print(f"🔎 Checking {cve_id} in {package} {installed_version} → {series} series")
    return False  # CVE is open or needs fixing
