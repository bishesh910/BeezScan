from beez_scanner.software_detector import get_installed_packages

pkgs = get_installed_packages()
print(f"✅ Found {len(pkgs)} packages.")
for name, version in pkgs[:10]:
    print(f"{name} - {version}")
