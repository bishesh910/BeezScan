import requests
import re
import os

def get_real_csv_url():
    print("🌐 Scraping MSRC export page...")
    html = requests.get("https://msrc.microsoft.com/update-guide/export", headers={"User-Agent": "Mozilla"}).text
    match = re.search(r'href="(https://aka\.ms/.*?\.csv)"', html)
    if not match:
        print("❌ Failed to find download URL.")
        return None
    redirect_url = match.group(1)
    # Follow the redirect
    print(f"🔁 Following redirect: {redirect_url}")
    resp = requests.get(redirect_url, allow_redirects=True)
    if resp.status_code == 200:
        return resp.content
    else:
        print(f"❌ Failed to download CSV: {resp.status_code}")
        return None

def save_csv(data):
    os.makedirs("data", exist_ok=True)
    path = "data/ms_kb_cve_map.csv"
    with open(path, "wb") as f:
        f.write(data)
    print(f"✅ CSV saved to {path}")

csv_data = get_real_csv_url()
if csv_data:
    save_csv(csv_data)
