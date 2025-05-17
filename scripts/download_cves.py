import os
import requests
import gzip
from tqdm import tqdm
import json


# Config
YEARS = list(range(2002, 2025))  # Adjust current year
BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
OUTPUT_DIR = "data/nvd_feeds"
MERGED_JSON = "data/all_cves.json"

os.makedirs(OUTPUT_DIR, exist_ok=True)


# Download and extract
def download_and_extract(year):
    fname = f"nvdcve-1.1-{year}.json.gz"
    url = BASE_URL + fname
    local_gz = os.path.join(OUTPUT_DIR, fname)
    local_json = local_gz[:-3]

    if os.path.exists(local_json):
        print(f"⏭️ Skipping {year}, already downloaded.")
        return

    r = requests.get(url, stream=True)
    if r.status_code == 200:
        with open(local_gz, "wb") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
        with gzip.open(local_gz, "rb") as f_in, open(local_json, "wb") as f_out:
            f_out.write(f_in.read())
        print(f"✅ {year} downloaded and extracted.")
    else:
        print(f"❌ Failed to fetch {year}: {r.status_code}")


# Merge all JSON into one list
def merge_all():
    all_items = []
    for year in tqdm(YEARS, desc="Merging"):
        path = os.path.join(OUTPUT_DIR, f"nvdcve-1.1-{year}.json")
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            items = json.load(f)["CVE_Items"]
            all_items.extend(items)

    with open(MERGED_JSON, "w", encoding="utf-8") as out:
        json.dump(all_items, out, indent=2)

    print(f"📦 Merged all CVEs into: {MERGED_JSON}")


# Main
if __name__ == "__main__":
    for year in YEARS:
        download_and_extract(year)
    merge_all()
