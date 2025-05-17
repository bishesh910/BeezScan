import os
import re
import bz2
import requests
import xml.etree.ElementTree as ET
from functools import lru_cache
from platform import release
import subprocess
from packaging import version


OVAL_BASE_URL = "https://www.redhat.com/security/data/oval"
OVAL_FEEDS = {
    "7": "com.redhat.rhsa-RHEL7.xml.bz2",
    "8": "com.redhat.rhsa-RHEL8.xml.bz2",
    "9": "com.redhat.rhsa-RHEL9.xml.bz2",
}

OVAL_CACHE_DIR = "data/oval_feeds"
os.makedirs(OVAL_CACHE_DIR, exist_ok=True)

@lru_cache
def get_rhel_major_version():
    try:
        with open("/etc/os-release") as f:
            lines = f.read()
        match = re.search(r"VERSION_ID=\"?(\d)", lines)
        return match.group(1) if match else None
    except Exception:
        return None

def download_oval_feed(rhel_version):
    feed_name = OVAL_FEEDS.get(rhel_version)
    if not feed_name:
        return None

    local_path = os.path.join(OVAL_CACHE_DIR, feed_name.replace(".bz2", ""))
    if os.path.exists(local_path):
        return local_path  # use cached

    print(f"📥 Downloading OVAL feed for RHEL {rhel_version}...")
    url = f"{OVAL_BASE_URL}/{feed_name}"
    resp = requests.get(url)
    if resp.status_code != 200:
        print(f"❌ Failed to download OVAL: {resp.status_code}")
        return None

    xml_data = bz2.decompress(resp.content)
    with open(local_path, "wb") as f:
        f.write(xml_data)

    return local_path

def parse_oval_feed(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    ns = {"oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}
    cve_data = {}

    for definition in root.findall(".//oval:definition", ns):
        cve_id = definition.get("id")
        for ref in definition.findall(".//oval:reference", ns):
            if ref.get("source") == "CVE":
                cve_id = ref.get("ref_id")

        for test in definition.findall(".//oval:criteria//oval:criterion", ns):
            comment = test.attrib.get("comment", "")
            m = re.search(r"is earlier than ([\w\.\-]+)", comment)
            pkg_match = re.search(r"([a-zA-Z0-9\-_+\.]+) is earlier than", comment)
            if m and pkg_match and cve_id:
                pkg = pkg_match.group(1)
                fixed_ver = m.group(1)
                cve_data.setdefault(pkg, {})[cve_id] = fixed_ver

    return cve_data

@lru_cache
def load_redhat_cve_data():
    version = get_rhel_major_version()
    if not version:
        print("⚠️ Not a RedHat-based OS or version not detected.")
        return {}

    xml_path = download_oval_feed(version)
    if not xml_path:
        return {}

    print(f"📖 Parsing OVAL data for RHEL {version}...")
    return parse_oval_feed(xml_path)



def get_installed_rpm_version(pkg_name):
    try:
        out = subprocess.check_output(
            ["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg_name],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
        return out if out and "is not installed" not in out else None
    except subprocess.CalledProcessError:
        return None

def is_cve_patched(cve_id, pkg_name):
    cve_map = load_redhat_cve_data()
    if pkg_name not in cve_map or cve_id not in cve_map[pkg_name]:
        return None  # no info

    fixed_version = cve_map[pkg_name][cve_id]
    installed_version = get_installed_rpm_version(pkg_name)

    if not installed_version:
        return None

    try:
        if version.parse(installed_version) >= version.parse(fixed_version):
            return True
        else:
            return False
    except:
        return None
