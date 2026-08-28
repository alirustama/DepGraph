"""
A realistic-shaped (fictionalized, not literal npm data) software supply
chain: internal projects that depend on open-source packages, which have
versions, which have their own transitive dependencies, some of which carry
disclosed vulnerabilities, all published by maintainers.

The shapes deliberately mirror real-world incidents (a tiny, widely-depended
transitive utility turning out to be the highest-risk node — see left-pad /
event-stream / log4j) so the "blast radius" and "maintainer risk" queries
have something interesting to surface.
"""

MAINTAINERS = [
    {"name": "Priya Raman", "email": "priya@oss-example.dev"},
    {"name": "Tom Whitfield", "email": "tom@oss-example.dev"},
    {"name": "Lena Ostrowski", "email": "lena@oss-example.dev"},
    {"name": "Kenji Sato", "email": "kenji@oss-example.dev"},
    {"name": "Marcus Bello", "email": "marcus@oss-example.dev"},
    {"name": "Ada Nkemelu", "email": "ada@oss-example.dev"},
]

PACKAGES = [
    {"name": "http-router", "ecosystem": "npm", "description": "Minimal HTTP routing for Node services"},
    {"name": "json-schema-lite", "ecosystem": "npm", "description": "Lightweight JSON schema validation"},
    {"name": "tiny-pad", "ecosystem": "npm", "description": "String padding utility used almost everywhere"},
    {"name": "date-fmt", "ecosystem": "npm", "description": "Date formatting helpers"},
    {"name": "log-stream", "ecosystem": "npm", "description": "Structured logging transport"},
    {"name": "yaml-parse", "ecosystem": "npm", "description": "YAML parser and serializer"},
    {"name": "retry-fetch", "ecosystem": "npm", "description": "HTTP fetch with retry/backoff"},
    {"name": "auth-jwt", "ecosystem": "npm", "description": "JWT signing and verification"},
    {"name": "img-resize", "ecosystem": "npm", "description": "Server-side image resizing"},
    {"name": "queue-lite", "ecosystem": "npm", "description": "In-memory + Redis-backed job queue"},
    {"name": "template-engine", "ecosystem": "npm", "description": "Lightweight HTML templating"},
    {"name": "csv-stream", "ecosystem": "npm", "description": "Streaming CSV reader/writer"},
    {"name": "cache-lru", "ecosystem": "npm", "description": "In-process LRU cache"},
    {"name": "config-loader", "ecosystem": "npm", "description": "Layered config/env loader"},
    {"name": "metrics-client", "ecosystem": "npm", "description": "StatsD-compatible metrics client"},
]

# Each version belongs to a package; deprecated + releaseDate are illustrative.
VERSIONS = [
    ("http-router", "3.2.0", "2025-02-10", False),
    ("http-router", "3.1.4", "2024-11-02", False),
    ("json-schema-lite", "1.9.0", "2025-05-01", False),
    ("json-schema-lite", "1.8.2", "2024-08-14", False),
    ("tiny-pad", "1.0.3", "2025-01-20", False),
    ("tiny-pad", "1.0.2", "2019-06-01", True),
    ("date-fmt", "2.4.1", "2025-03-11", False),
    ("log-stream", "0.9.6", "2025-06-18", False),
    ("log-stream", "0.9.5", "2025-02-02", False),
    ("yaml-parse", "4.1.0", "2024-12-05", False),
    ("yaml-parse", "4.0.7", "2023-09-19", False),
    ("retry-fetch", "2.2.3", "2025-04-22", False),
    ("auth-jwt", "5.0.1", "2025-07-01", False),
    ("auth-jwt", "4.8.9", "2024-01-15", False),
    ("img-resize", "1.6.0", "2025-05-30", False),
    ("queue-lite", "3.0.0", "2025-06-01", False),
    ("template-engine", "2.1.2", "2024-10-08", False),
    ("csv-stream", "1.3.0", "2025-01-09", False),
    ("cache-lru", "1.1.5", "2024-07-20", False),
    ("config-loader", "2.0.4", "2025-03-28", False),
    ("metrics-client", "1.2.1", "2024-09-11", False),
]

MAINTAINS = [
    ("Priya Raman", "http-router"),
    ("Priya Raman", "retry-fetch"),
    ("Tom Whitfield", "json-schema-lite"),
    # tiny-pad is the "left-pad" of this graph: one maintainer, everyone depends on it.
    ("Lena Ostrowski", "tiny-pad"),
    ("Lena Ostrowski", "date-fmt"),
    ("Kenji Sato", "log-stream"),
    ("Kenji Sato", "yaml-parse"),
    ("Kenji Sato", "metrics-client"),
    ("Marcus Bello", "auth-jwt"),
    ("Marcus Bello", "img-resize"),
    ("Ada Nkemelu", "queue-lite"),
    ("Ada Nkemelu", "template-engine"),
    ("Ada Nkemelu", "csv-stream"),
    ("Ada Nkemelu", "cache-lru"),
    ("Ada Nkemelu", "config-loader"),
]

# (fromPackage, fromVersion) -[:DEPENDS_ON]-> toPackage, versionRange, dependencyType
DEPENDS_ON = [
    ("http-router", "3.2.0", "json-schema-lite", "^1.9.0", "direct"),
    ("http-router", "3.2.0", "log-stream", "^0.9.5", "direct"),
    ("http-router", "3.1.4", "log-stream", "^0.9.5", "direct"),
    ("json-schema-lite", "1.9.0", "tiny-pad", "^1.0.2", "direct"),
    ("json-schema-lite", "1.8.2", "tiny-pad", "^1.0.2", "direct"),
    ("date-fmt", "2.4.1", "tiny-pad", "^1.0.2", "direct"),
    ("log-stream", "0.9.6", "tiny-pad", "^1.0.2", "direct"),
    ("log-stream", "0.9.6", "config-loader", "^2.0.0", "direct"),
    ("log-stream", "0.9.5", "tiny-pad", "^1.0.2", "direct"),
    ("yaml-parse", "4.1.0", "tiny-pad", "^1.0.2", "direct"),
    ("retry-fetch", "2.2.3", "date-fmt", "^2.4.0", "direct"),
    ("retry-fetch", "2.2.3", "log-stream", "^0.9.5", "direct"),
    ("auth-jwt", "5.0.1", "json-schema-lite", "^1.9.0", "direct"),
    ("auth-jwt", "4.8.9", "json-schema-lite", "^1.8.0", "direct"),
    ("img-resize", "1.6.0", "log-stream", "^0.9.5", "direct"),
    ("img-resize", "1.6.0", "metrics-client", "^1.2.0", "direct"),
    ("queue-lite", "3.0.0", "retry-fetch", "^2.2.0", "direct"),
    ("queue-lite", "3.0.0", "log-stream", "^0.9.5", "direct"),
    ("template-engine", "2.1.2", "date-fmt", "^2.4.0", "direct"),
    ("template-engine", "2.1.2", "yaml-parse", "^4.1.0", "direct"),
    ("csv-stream", "1.3.0", "date-fmt", "^2.4.0", "direct"),
    ("cache-lru", "1.1.5", "metrics-client", "^1.2.0", "direct"),
    ("config-loader", "2.0.4", "yaml-parse", "^4.1.0", "direct"),
    ("config-loader", "2.0.4", "json-schema-lite", "^1.9.0", "direct"),
]

VULNERABILITIES = [
    {
        "cveId": "CVE-2026-10432",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "summary": "Prototype pollution in tiny-pad 1.0.2 allows remote code execution via crafted input strings.",
        "publishedDate": "2026-07-30",
        "package": "tiny-pad",
        "version": "1.0.2",
        "patchedInVersion": "1.0.3",
    },
    {
        "cveId": "CVE-2026-8821",
        "severity": "HIGH",
        "cvss": 7.5,
        "summary": "yaml-parse 4.0.7 deserializes arbitrary types, enabling object injection from untrusted YAML.",
        "publishedDate": "2026-05-12",
        "package": "yaml-parse",
        "version": "4.0.7",
        "patchedInVersion": "4.1.0",
    },
    {
        "cveId": "CVE-2026-4410",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "summary": "auth-jwt 4.8.9 accepts tokens signed with the 'none' algorithm under a non-default config.",
        "publishedDate": "2026-02-19",
        "package": "auth-jwt",
        "version": "4.8.9",
        "patchedInVersion": "5.0.1",
    },
    {
        "cveId": "CVE-2026-2207",
        "severity": "LOW",
        "cvss": 3.1,
        "summary": "log-stream 0.9.5 writes secrets to debug logs when LOG_LEVEL=trace is misconfigured.",
        "publishedDate": "2026-01-05",
        "package": "log-stream",
        "version": "0.9.5",
        "patchedInVersion": "0.9.6",
    },
]

PROJECTS = [
    {"name": "checkout-service", "description": "Handles cart & payment for the storefront", "owner": "Commerce team"},
    {"name": "notifications-api", "description": "Sends email/SMS/push notifications", "owner": "Growth team"},
    {"name": "admin-dashboard", "description": "Internal ops dashboard", "owner": "Platform team"},
    {"name": "image-pipeline", "description": "Resizes and optimizes uploaded media", "owner": "Media team"},
    {"name": "billing-worker", "description": "Async billing/invoice generation", "owner": "Finance eng"},
]

# (project, package, versionRange)
REQUIRES = [
    ("checkout-service", "http-router", "^3.2.0"),
    ("checkout-service", "auth-jwt", "^5.0.0"),
    ("checkout-service", "retry-fetch", "^2.2.0"),
    ("notifications-api", "queue-lite", "^3.0.0"),
    ("notifications-api", "template-engine", "^2.1.0"),
    ("notifications-api", "http-router", "^3.1.0"),
    ("admin-dashboard", "http-router", "^3.2.0"),
    ("admin-dashboard", "csv-stream", "^1.3.0"),
    ("admin-dashboard", "auth-jwt", "^4.8.0"),
    ("image-pipeline", "img-resize", "^1.6.0"),
    ("image-pipeline", "queue-lite", "^3.0.0"),
    ("billing-worker", "config-loader", "^2.0.0"),
    ("billing-worker", "cache-lru", "^1.1.0"),
    ("billing-worker", "retry-fetch", "^2.2.0"),
]
