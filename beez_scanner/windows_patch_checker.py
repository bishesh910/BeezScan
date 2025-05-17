import subprocess
import csv
import os
from functools import lru_cache

KB_CVE_CSV = "data/ms_kb_cve_map.csv"
os.makedirs("data", exist_ok=True)

@lru_cache
def get_installed_kbs():
    try:
        output = subprocess.check_output(["wmic", "qfe", "list", "brief"], text=True, stderr=subprocess.DEVNULL)
        lines = output.strip().splitlines()
        kbs = []
        for line in lines:
            if "KB" in line:
                parts = line.split()
                for p in parts:
                    if p.startswith("KB"):
                        kbs.append(p.upper())
        return kbs
    except Exception as e:
        print(f"⚠️ Failed to get installed KBs: {e}")
        return []

@lru_cache
def load_kb_cve_map():
    cve_map = {}
    if not os.path.exists(KB_CVE_CSV):
        print("❌ CSV file not found.")
        return cve_map

    with open(KB_CVE_CSV, mode='r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_id = row.get('CVE ID')
            kb_article = row.get('KB Article')
            if cve_id and kb_article:
                cve_map.setdefault(cve_id.strip().upper(), []).append(kb_article.strip().upper())
    return cve_map

def is_cve_patched(cve_id):
    cve_id = cve_id.strip().upper()
    installed = get_installed_kbs()
    cve_map = load_kb_cve_map()
    kbs_for_cve = cve_map.get(cve_id)
    if not kbs_for_cve:
        return None

    for kb in kbs_for_cve:
        if kb in installed:
            return True
    return False
