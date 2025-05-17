import json
from datetime import datetime
from matplotlib import pyplot as plt
from jinja2 import Environment, FileSystemLoader
import base64
from io import BytesIO
import os
from packaging import version
from collections import defaultdict
import platform

IS_WINDOWS = platform.system().lower() == "windows"
if not IS_WINDOWS:
    from weasyprint import HTML


def count_severity(vulns):
    sev_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for v in vulns:
        score = v.get("cvss_v3")
        if score is None:
            continue
        elif score < 4:
            sev_counts["low"] += 1
        elif score < 7:
            sev_counts["medium"] += 1
        elif score < 9:
            sev_counts["high"] += 1
        else:
            sev_counts["critical"] += 1
    return sev_counts


def load_latest_result():
    result_files = sorted(
        [
            f
            for f in os.listdir("results")
            if f.startswith("scan_") and f.endswith(".json")
        ],
        reverse=True,
    )
    if not result_files:
        raise FileNotFoundError("No result files found in /results.")
    with open(os.path.join("results", result_files[0]), "r") as f:
        return json.load(f)


def parse_software_from_cpe(cpe_uri):
    try:
        parts = cpe_uri.split(":")
        vendor, product = parts[3], parts[4]
        return f"{vendor}:{product}"
    except:
        return "unknown"


def generate_pie_chart_by_severity(vulns):
    buckets = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}
    for v in vulns:
        score = v.get("cvss_v3")
        if score is None:
            buckets["UNKNOWN"] += 1
        elif score < 4:
            buckets["LOW"] += 1
        elif score < 7:
            buckets["MEDIUM"] += 1
        elif score < 9:
            buckets["HIGH"] += 1
        else:
            buckets["CRITICAL"] += 1

    labels = [f"{level} ({count})" for level, count in buckets.items()]
    fig, ax = plt.subplots()
    wedges, texts = ax.pie(buckets.values(), labels=labels, startangle=90)
    ax.axis("equal")
    ax.set_title("CVEs by Severity")

    buf = BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def load_logo_base64():
    logo_path = os.path.join("templates", "BeezScan_logo.png")
    with open(logo_path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def compute_group_summary(grouped):
    summary = []
    for software, vulns in grouped.items():
        cvss_scores = [v.get("cvss_v3") for v in vulns if v.get("cvss_v3") is not None]
        avg_score = (
            round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0.0
        )
        max_score = round(max(cvss_scores), 2) if cvss_scores else 0.0
        summary.append(
            {
                "software": software,
                "count": len(vulns),
                "avg_cvss": avg_score,
                "max_cvss": max_score,
            }
        )
    return sorted(summary, key=lambda x: x["avg_cvss"], reverse=True)


def generate_report():
    data = load_latest_result()
    all_vulns = [
        v
        for v in data["vulnerabilities"]
        if v.get("patched") is not True and v.get("status") != "safe"
    ]
    sev_counts = count_severity(all_vulns)
    for v in all_vulns:
        v["software"] = parse_software_from_cpe(v.get("cpe", ""))

    grouped = defaultdict(list)
    for v in all_vulns:
        grouped[v["software"]].append(v)

    for software in grouped:
        grouped[software] = sorted(
            grouped[software], key=lambda v: -(v.get("cvss_v3") or 0)
        )

    pie_chart_b64 = generate_pie_chart_by_severity(all_vulns)
    group_summary = compute_group_summary(grouped)
    logo_b64 = load_logo_base64()

    grouped_sorted = {
        item["software"]: grouped[item["software"]]
        for item in group_summary
        if item["software"] in grouped
    }

    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")
    timestamp = datetime.fromisoformat(data["scanned_at"]).strftime(
        "%d %B %Y, %I:%M %p"
    )

    html_out = template.render(
        title="BeezScan Vulnerability Results",
        timestamp=timestamp,
        total_packages=data["total_packages"],
        total_vulnerabilities=len(all_vulns),
        grouped_vulnerabilities=grouped_sorted,
        group_summary=group_summary,
        pie_chart_data=pie_chart_b64,
        logo_b64=logo_b64,
        sev_counts=sev_counts,
    )

    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"results/BeezScan_Report_{now}"

    html_path = output_path + ".html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    print(f"✅ HTML report generated: {html_path}")


if __name__ == "__main__":
    generate_report()
