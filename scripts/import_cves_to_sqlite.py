import sqlite3
import json
from tqdm import tqdm
import os

# Paths
JSON_FILE = "data/all_cves.json"
DB_FILE = "data/cves.db"

# Create SQLite connection
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

# Create CVEs table
cursor.execute("""
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    published TEXT,
    modified TEXT,
    cvss_v3 REAL,
    severity TEXT,
    cwe TEXT,
    cpes TEXT,
    reference_urls TEXT
)
""")

# Create CPE match table (structured for version-aware matching)
cursor.execute("""
CREATE TABLE IF NOT EXISTS cpe_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,
    cpe_uri TEXT,
    vulnerable INTEGER,
    versionStartIncluding TEXT,
    versionStartExcluding TEXT,
    versionEndIncluding TEXT,
    versionEndExcluding TEXT
)
""")

# Load CVEs from JSON
if not os.path.exists(JSON_FILE):
    print(f"❌ Error: {JSON_FILE} not found. Run download_cves.py first.")
    exit(1)

with open(JSON_FILE, "r") as f:
    cves = json.load(f)

# Insert each CVE entry
for item in tqdm(cves, desc="📥 Inserting CVEs"):
    try:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        published = item.get("publishedDate", "")
        modified = item.get("lastModifiedDate", "")

        # CVSS
        impact = item.get("impact", {})
        cvss = impact.get("baseMetricV3", {}).get("cvssV3", {})
        cvss_v3 = cvss.get("baseScore", None)
        severity = cvss.get("baseSeverity", None)

        # CWE
        cwe = ""
        pt_data = item["cve"]["problemtype"]["problemtype_data"]
        if pt_data:
            descriptions = pt_data[0].get("description", [])
            if descriptions:
                cwe = descriptions[0].get("value", "")

        # References
        refs = [ref["url"] for ref in item["cve"]["references"]["reference_data"]]
        ref_str = ";".join(refs)

        # CPEs (for old-style display)
        cpes = []
        nodes = item.get("configurations", {}).get("nodes", [])
        for node in nodes:
            for cpe in node.get("cpe_match", []):
                if cpe.get("vulnerable"):
                    cpes.append(cpe.get("cpe23Uri", ""))

                # Insert into cpe_matches table
                cpe_uri = cpe.get("cpe23Uri", "")
                vulnerable = int(cpe.get("vulnerable", False))
                vs_inc = cpe.get("versionStartIncluding")
                vs_exc = cpe.get("versionStartExcluding")
                ve_inc = cpe.get("versionEndIncluding")
                ve_exc = cpe.get("versionEndExcluding")

                cursor.execute("""
                    INSERT INTO cpe_matches (
                        cve_id, cpe_uri, vulnerable,
                        versionStartIncluding, versionStartExcluding,
                        versionEndIncluding, versionEndExcluding
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (cve_id, cpe_uri, vulnerable,
                      vs_inc, vs_exc, ve_inc, ve_exc))

        cpe_str = ";".join(cpes)

        # Insert CVE record
        cursor.execute("""
            INSERT OR IGNORE INTO cves (
                cve_id, description, published, modified,
                cvss_v3, severity, cwe, cpes, reference_urls
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (cve_id, description, published, modified,
              cvss_v3, severity, cwe, cpe_str, ref_str))

    except Exception as e:
        print(f"⚠️ Failed to insert {item['cve']['CVE_data_meta']['ID']}: {e}")

# Finalize
conn.commit()

cursor.execute("SELECT COUNT(*) FROM cves")
print(f"✅ Inserted {cursor.fetchone()[0]} CVEs into cves table.")

cursor.execute("SELECT COUNT(*) FROM cpe_matches")
print(f"✅ Inserted {cursor.fetchone()[0]} structured CPE matches into cpe_matches table.")

conn.close()
