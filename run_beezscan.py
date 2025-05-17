import os
import subprocess

print("🔍 Running BeezScan vulnerability scan...")

# Run the scanner
subprocess.run(["python", "scripts/save_scan_results.py"])

# Ask if user wants a PDF report
choice = input("🖨️  Generate PDF report now? (y/n): ").strip().lower()
if choice == "y":
    subprocess.run(["python", "scripts/reporter.py"])
else:
    print("📄 PDF report skipped.")
