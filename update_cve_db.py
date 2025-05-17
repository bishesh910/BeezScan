import subprocess

print("🔄 Updating CVE database from NVD...")

# Download feeds
subprocess.run(["python", "scripts/download_cves.py"])

# Import into SQLite
subprocess.run(["python", "scripts/import_cves_to_sqlite.py"])

print("✅ CVE database update complete.")
