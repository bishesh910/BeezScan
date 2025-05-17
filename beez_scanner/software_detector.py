import os
import platform
import subprocess
import re
from beez_scanner.macos_software_detector import (
    get_installed_software as get_macos_software,
)


def get_installed_packages():
    system = platform.system().lower()

    if system == "linux":
        return get_linux_packages()
    elif system == "darwin":
        return get_macos_software()
    elif system == "windows":
        return get_windows_packages()
    else:
        print(f"⚠️ Unsupported system: {system}")
        return []


def get_linux_packages():
    if os.path.exists("/usr/bin/dpkg"):
        return get_dpkg_packages()
    elif os.path.exists("/bin/rpm") or os.path.exists("/usr/bin/rpm"):
        return get_rpm_packages()
    else:
        return []


def get_dpkg_packages():
    try:
        output = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${Package} ${Version}\n"], text=True
        )
        lines = output.strip().splitlines()
        return [tuple(line.split()[:2]) for line in lines]
    except Exception:
        return []


def get_rpm_packages():
    try:
        output = subprocess.check_output(
            ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"], text=True
        )
        lines = output.strip().splitlines()
        return [tuple(line.split()[:2]) for line in lines]
    except Exception:
        return []


def get_windows_packages():
    try:
        output = subprocess.check_output(
            ["wmic", "product", "get", "name,version"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        lines = output.strip().splitlines()[1:]  # Skip header
        pkgs = []
        for line in lines:
            parts = line.strip().rsplit(" ", 1)
            if len(parts) == 2:
                name, version = parts
                pkgs.append((name.strip(), version.strip()))
        return pkgs
    except Exception as e:
        print(f"⚠️ Failed to get Windows packages: {e}")
        return []
