"""
Loads app/seed_data.py into CognoDB.

Usage:
    python scripts/seed.py            # wipe + reload
    python scripts/seed.py --no-wipe  # merge without deleting existing data
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import seed_data as data
from app.db import run_query, verify_connectivity, close_driver
from app.queries import wipe_database, merge_node, merge_relationship


def main() -> None:
    wipe = "--no-wipe" not in sys.argv

    ok, message = verify_connectivity()
    if not ok:
        print(f"✗ Cannot reach CognoDB: {message}")
        print("  Check your .env file against .env.example and confirm the instance is running.")
        sys.exit(1)
    print("✓ Connected to CognoDB")

    if wipe:
        print("• Wiping existing graph...")
        wipe_database()

    print("• Creating uniqueness constraints...")
    for label, prop in [
        ("Project", "name"), ("Package", "name"), ("Vulnerability", "cveId"),
        ("Maintainer", "email"), ("Version", "key"),
    ]:
        run_query(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE")

    print(f"• Loading {len(data.MAINTAINERS)} maintainers...")
    for m in data.MAINTAINERS:
        merge_node("Maintainer", "email", m["email"], m)

    print(f"• Loading {len(data.PACKAGES)} packages...")
    for p in data.PACKAGES:
        merge_node("Package", "name", p["name"], p)

    print(f"• Loading {len(data.VERSIONS)} versions...")
    for pkg, number, released, deprecated in data.VERSIONS:
        version_key = f"{pkg}@{number}"
        merge_node("Version", "key", version_key, {
            "key": version_key, "number": number, "releaseDate": released, "deprecated": deprecated,
        })
        merge_relationship("Package", "name", pkg, "HAS_VERSION", "Version", "key", version_key)

    print(f"• Wiring {len(data.MAINTAINS)} maintainer relationships...")
    for maintainer_name, pkg in data.MAINTAINS:
        email = next(m["email"] for m in data.MAINTAINERS if m["name"] == maintainer_name)
        merge_relationship("Maintainer", "email", email, "MAINTAINS", "Package", "name", pkg)

    print(f"• Wiring {len(data.DEPENDS_ON)} DEPENDS_ON edges...")
    for from_pkg, from_ver, to_pkg, version_range, dep_type in data.DEPENDS_ON:
        merge_relationship(
            "Version", "key", f"{from_pkg}@{from_ver}",
            "DEPENDS_ON",
            "Package", "name", to_pkg,
            {"versionRange": version_range, "dependencyType": dep_type},
        )

    print(f"• Loading {len(data.VULNERABILITIES)} vulnerabilities...")
    for v in data.VULNERABILITIES:
        merge_node("Vulnerability", "cveId", v["cveId"], {
            "cveId": v["cveId"], "severity": v["severity"], "cvss": v["cvss"],
            "summary": v["summary"], "publishedDate": v["publishedDate"],
        })
        merge_relationship(
            "Version", "key", f"{v['package']}@{v['version']}",
            "AFFECTED_BY",
            "Vulnerability", "cveId", v["cveId"],
            {"patchedInVersion": v["patchedInVersion"]},
        )

    print(f"• Loading {len(data.PROJECTS)} projects...")
    for proj in data.PROJECTS:
        merge_node("Project", "name", proj["name"], proj)

    print(f"• Wiring {len(data.REQUIRES)} REQUIRES edges...")
    for project, pkg, version_range in data.REQUIRES:
        merge_relationship(
            "Project", "name", project,
            "REQUIRES",
            "Package", "name", pkg,
            {"versionRange": version_range},
        )

    close_driver()
    print("\n✓ Seed complete.")


if __name__ == "__main__":
    main()
