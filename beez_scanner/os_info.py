import platform
import distro

def get_os_info():
    """
    Returns a dict with OS family, distro, version, and pretty name.
    """
    sysname = platform.system().lower()

    if sysname == "linux":
        return {
            "family": "linux",
            "distro": distro.id().lower(),       # e.g. ubuntu
            "version": distro.version(),         # e.g. 24.04
            "pretty": distro.name(pretty=True)   # e.g. Ubuntu 24.04 LTS
        }
    elif sysname == "windows":
        return {
            "family": "windows",
            "distro": "windows",
            "version": platform.release(),
            "pretty": platform.platform()
        }
    elif sysname == "darwin":
        return {
            "family": "macos",
            "distro": "macos",
            "version": platform.mac_ver()[0],
            "pretty": "macOS " + platform.mac_ver()[0]
        }

    return {
        "family": "unknown",
        "distro": "unknown",
        "version": "unknown",
        "pretty": "Unknown OS"
    }
