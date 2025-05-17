import subprocess
import platform
import re

def get_macos_info():
    return {
        "os": "macos",
        "version": platform.mac_ver()[0],
        "product": platform.platform()
    }

def get_homebrew_packages():
    try:
        output = subprocess.check_output(["brew", "list", "--versions"], text=True)
        pkgs = []
        for line in output.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]
                pkgs.append((name, version))
        return pkgs
    except Exception:
        return []

def get_system_apps():
    try:
        output = subprocess.check_output(["system_profiler", "SPApplicationsDataType"], text=True)
        apps = []
        current_app = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if re.match(r"^[A-Za-z].*:$", line):
                if current_app.get("name") and current_app.get("version"):
                    apps.append((current_app["name"], current_app["version"]))
                current_app = {"name": line[:-1]}
            elif "Version:" in line:
                version = line.split("Version:")[1].strip()
                current_app["version"] = version
        return apps
    except Exception:
        return []

def get_installed_software():
    apps = get_homebrew_packages() + get_system_apps()
    seen = set()
    unique_apps = []
    for name, ver in apps:
        key = (name.lower(), ver)
        if key not in seen:
            seen.add(key)
            unique_apps.append((name, ver))
    return unique_apps
