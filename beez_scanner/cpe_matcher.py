import sqlite3
import re
import platform
from packaging import version
from tqdm import tqdm
from beez_scanner.os_info import get_os_info
from beez_scanner.ubuntu_patch_checker import is_cve_patched as is_ubuntu_patched
from beez_scanner.redhat_patch_checker import is_cve_patched as is_redhat_patched
from beez_scanner.windows_patch_checker import is_cve_patched as is_windows_patched


def normalize_ver(v):
    return re.sub(r"[^\d\.a-zA-Z\-]", "", v)


def get_kernel_version():
    return platform.release().split("-")[0]


def version_in_range(installed, start_inc, start_exc, end_inc, end_exc):
    try:
        v_inst = version.parse(installed)
        if start_inc and v_inst < version.parse(start_inc):
            return False
        if start_exc and v_inst <= version.parse(start_exc):
            return False
        if end_inc and v_inst > version.parse(end_inc):
            return False
        if end_exc and v_inst >= version.parse(end_exc):
            return False
        return True
    except:
        return False


def match_packages_to_cves(packages, db_path="data/cves.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    os_info = get_os_info()
    distro = os_info["distro"]
    os_version = os_info["version"]
    family = os_info["family"]
    kernel_version = get_kernel_version()

    print(f"🔍 Host OS: {distro} {os_version} ({family})")
    print(f"🔍 Kernel: {kernel_version}")

    UNRELATED_DISTROS = [
        "windows", "macos", "darwin", "microsoft", "oracle",
        "suse", "vmware", "android", "freebsd"
    ]
    if distro.lower() not in ("macos", "darwin", "osx", "apple"):
        UNRELATED_DISTROS += ["macos", "darwin", "osx", "apple"]

    if distro in UNRELATED_DISTROS:
        UNRELATED_DISTROS.remove(distro)

    results = []

    for name, ver in tqdm(packages, desc="🔎 Deep vulnerability scan"):
        if not ver:
            continue

        norm_ver = normalize_ver(ver)
        try:
            local_version = version.parse(norm_ver)
        except Exception:
            continue

        like_clause = f"%{name.lower()}%"
        cursor.execute("""
            SELECT cve_id, cpe_uri, vulnerable,
                   versionStartIncluding, versionStartExcluding,
                   versionEndIncluding, versionEndExcluding
            FROM cpe_matches
            WHERE LOWER(cpe_uri) LIKE ?
              AND vulnerable = 1
        """, (like_clause,))
        matches = cursor.fetchall()

        for (cve_id, cpe_uri, _, vs_inc, vs_exc, ve_inc, ve_exc) in matches:
            cpe_lower = cpe_uri.lower()

            # 🛡 OS filtering
            if any(d in cpe_lower for d in UNRELATED_DISTROS):
                continue

            # ❌ Skip RedHat-specific CPEs if not on RedHat
            if "redhat" in cpe_lower or "rhel" in cpe_lower:
                if distro not in ("rhel", "redhat", "centos", "rocky"):
                    continue

            distro_matches = f":{distro}_" in cpe_lower or f":{distro}:" in cpe_lower
            vendor_matches = any(v in cpe_lower for v in ["canonical", distro])
            family_matches = distro in cpe_lower or f":{family}:" in cpe_lower

            if not (distro_matches or vendor_matches or family_matches):
                continue

            is_kernel = "linux_kernel" in cpe_lower
            installed_ver = kernel_version if is_kernel else norm_ver

            if version_in_range(installed_ver, vs_inc, vs_exc, ve_inc, ve_exc):
                status = "vulnerable"
                match_level = "Likely"
            elif all(x is None for x in [vs_inc, vs_exc, ve_inc, ve_exc]):
                status = "possible"
                match_level = "Possible"
            else:
                status = "safe"
                match_level = "Safe"

            cursor.execute("SELECT description, cvss_v3 FROM cves WHERE cve_id = ?", (cve_id,))
            cve_row = cursor.fetchone()
            if not cve_row:
                continue
            desc, score = cve_row

            # ✅ Patch checking
            patched = None
            distro_lower = distro.lower()

            if "ubuntu" in distro_lower:
                patched = is_ubuntu_patched(cve_id, name, norm_ver)
            elif distro_lower in ("rhel", "redhat", "centos", "rocky"):
                patched = is_redhat_patched(cve_id, name)
            elif distro_lower.startswith("windows"):
                patched = is_windows_patched(cve_id)
            elif distro_lower in ("macos", "darwin", "osx", "apple"):
                patched = None  # macOS patching not implemented

            if patched is True:
                continue  # skip known patched

            results.append({
                "package": name,
                "installed_version": str(local_version),
                "cve_id": cve_id,
                "cvss_v3": score,
                "cpe": cpe_uri,
                "description": desc,
                "status": status,
                "match_level": match_level,
                "patched": patched
            })

    conn.close()
    return results
