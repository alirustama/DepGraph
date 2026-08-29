"""
Every Cypher statement DepGraph runs lives here, as a small function returning
plain dicts. All parameters are passed through the driver's parameter binding
(session.run(query, **params)) — nothing is ever string-concatenated into a
query, per the assignment's requirement.
"""
from app.db import run_query, run_query_raw, run_write

MAX_HOPS = 6  # cap on variable-length traversals so a bad graph can't blow up the query


# --------------------------------------------------------------------------
# Dashboard / listing queries
# --------------------------------------------------------------------------

def list_projects() -> list[dict]:
    return run_query(
        """
        MATCH (p:Project)
        OPTIONAL MATCH (p)-[:REQUIRES]->(pkg:Package)
        RETURN p.name AS name, p.description AS description, p.owner AS owner,
               count(DISTINCT pkg) AS directDependencies
        ORDER BY p.name
        """
    )


def list_packages() -> list[dict]:
    return run_query(
        """
        MATCH (pkg:Package)
        OPTIONAL MATCH (pkg)-[:HAS_VERSION]->(v:Version)-[:AFFECTED_BY]->(vuln:Vulnerability)
        RETURN pkg.name AS name, pkg.ecosystem AS ecosystem, pkg.description AS description,
               count(DISTINCT vuln) AS vulnerabilityCount
        ORDER BY vulnerabilityCount DESC, pkg.name
        """
    )


def list_vulnerabilities() -> list[dict]:
    return run_query(
        """
        MATCH (vuln:Vulnerability)<-[:AFFECTED_BY]-(v:Version)<-[:HAS_VERSION]-(pkg:Package)
        RETURN vuln.cveId AS cveId, vuln.severity AS severity, vuln.cvss AS cvss,
               vuln.summary AS summary, vuln.publishedDate AS publishedDate,
               collect(DISTINCT pkg.name) AS affectedPackages
        ORDER BY vuln.cvss DESC
        """
    )


# --------------------------------------------------------------------------
# Project detail — multi-hop transitive dependency walk (>= 2 hops)
# --------------------------------------------------------------------------

def project_detail(project: str) -> dict | None:
    rows = run_query(
        "MATCH (p:Project {name: $project}) RETURN p.name AS name, p.description AS description, p.owner AS owner",
        project=project,
    )
    if not rows:
        return None
    info = rows[0]

    direct = run_query(
        """
        MATCH (:Project {name: $project})-[r:REQUIRES]->(pkg:Package)
        RETURN pkg.name AS package, pkg.ecosystem AS ecosystem, r.versionRange AS versionRange
        ORDER BY pkg.name
        """,
        project=project,
    )

    # The multi-hop traversal: everything reachable from the project's direct
    # requirements by walking DEPENDS_ON any number of times (0..MAX_HOPS).
    transitive = run_query(
        f"""
        MATCH (:Project {{name: $project}})-[:REQUIRES]->(:Package)-[:HAS_VERSION]->(v:Version)
        MATCH path = (v)-[:DEPENDS_ON*0..{MAX_HOPS}]->(dep:Package)
        RETURN DISTINCT dep.name AS package, min(length(path)) AS hops
        ORDER BY hops, package
        """,
        project=project,
    )

    vulnerabilities = run_query(
        f"""
        MATCH (:Project {{name: $project}})-[:REQUIRES]->(:Package)-[:HAS_VERSION]->(v0:Version)
        MATCH path = (v0)-[:DEPENDS_ON*0..{MAX_HOPS}]->(:Package)-[:HAS_VERSION]->(badVersion:Version)-[:AFFECTED_BY]->(vuln:Vulnerability)
        RETURN DISTINCT vuln.cveId AS cveId, vuln.severity AS severity, vuln.cvss AS cvss,
               badVersion.number AS vulnerableVersion, min(length(path)) AS hops
        ORDER BY vuln.cvss DESC
        """,
        project=project,
    )

    return {
        **info,
        "directDependencies": direct,
        "transitiveDependencies": transitive,
        "vulnerabilities": vulnerabilities,
    }


# --------------------------------------------------------------------------
# Package detail — reverse traversal (who depends on this?)
# --------------------------------------------------------------------------

def package_detail(package: str) -> dict | None:
    rows = run_query(
        "MATCH (pkg:Package {name: $package}) RETURN pkg.name AS name, pkg.ecosystem AS ecosystem, pkg.description AS description",
        package=package,
    )
    if not rows:
        return None
    info = rows[0]

    versions = run_query(
        """
        MATCH (:Package {name: $package})-[:HAS_VERSION]->(v:Version)
        OPTIONAL MATCH (v)-[:AFFECTED_BY]->(vuln:Vulnerability)
        RETURN v.number AS number, v.releaseDate AS releaseDate, v.deprecated AS deprecated,
               collect(DISTINCT vuln.cveId) AS cves
        ORDER BY v.releaseDate DESC
        """,
        package=package,
    )

    maintainers = run_query(
        """
        MATCH (m:Maintainer)-[:MAINTAINS]->(:Package {name: $package})
        RETURN m.name AS name, m.email AS email
        ORDER BY m.name
        """,
        package=package,
    )

    # Reverse multi-hop traversal: every package/project that transitively depends on this one.
    dependents = run_query(
        f"""
        MATCH (dependent:Package)-[:HAS_VERSION]->(:Version)-[:DEPENDS_ON*1..{MAX_HOPS}]->(:Package {{name: $package}})
        RETURN DISTINCT dependent.name AS package
        ORDER BY package
        """,
        package=package,
    )

    exposed_projects = run_query(
        f"""
        MATCH (proj:Project)-[:REQUIRES]->(:Package)-[:HAS_VERSION]->(:Version)-[:DEPENDS_ON*0..{MAX_HOPS}]->(:Package {{name: $package}})
        RETURN DISTINCT proj.name AS project
        ORDER BY project
        """,
        package=package,
    )

    return {
        **info,
        "versions": versions,
        "maintainers": maintainers,
        "dependents": dependents,
        "exposedProjects": exposed_projects,
    }


# --------------------------------------------------------------------------
# Vulnerability blast radius — the "relational DB finds this awkward" query
# --------------------------------------------------------------------------

def vulnerability_blast_radius(cve: str) -> dict | None:
    meta = run_query(
        "MATCH (v:Vulnerability {cveId: $cve}) RETURN v.cveId AS cveId, v.severity AS severity, v.cvss AS cvss, v.summary AS summary, v.publishedDate AS publishedDate",
        cve=cve,
    )
    if not meta:
        return None

    # patchedInVersion lives on the AFFECTED_BY relationship, not the node.
    affected_packages = run_query(
        """
        MATCH (:Vulnerability {cveId: $cve})<-[r:AFFECTED_BY]-(v:Version)<-[:HAS_VERSION]-(pkg:Package)
        RETURN pkg.name AS package, v.number AS version, r.patchedInVersion AS patchedInVersion
        """,
        cve=cve,
    )

    exposed_projects = run_query(
        f"""
        MATCH (vuln:Vulnerability {{cveId: $cve}})<-[:AFFECTED_BY]-(badVersion:Version)<-[:HAS_VERSION]-(badPkg:Package)
        MATCH path = (proj:Project)-[:REQUIRES]->(:Package)-[:HAS_VERSION]->(:Version)-[:DEPENDS_ON*0..{MAX_HOPS}]->(badPkg)
        RETURN DISTINCT proj.name AS project, min(length(path)) AS hops,
               [n IN nodes(path) | coalesce(n.name, n.number)] AS examplePath
        ORDER BY hops, project
        """,
        cve=cve,
    )

    return {
        **meta[0],
        "affectedPackages": affected_packages,
        "exposedProjects": exposed_projects,
    }


# --------------------------------------------------------------------------
# Shortest path — "what's the minimal chain connecting these two things"
# --------------------------------------------------------------------------

def shortest_path(project: str, package: str) -> dict | None:
    rows = run_query(
        f"""
        MATCH (proj:Project {{name: $project}}), (pkg:Package {{name: $package}})
        MATCH path = shortestPath((proj)-[:REQUIRES|DEPENDS_ON*1..{MAX_HOPS + 2}]-(pkg))
        RETURN [n IN nodes(path) | coalesce(n.name, n.number)] AS chain,
               [r IN relationships(path) | type(r)] AS relationshipTypes,
               length(path) AS hops
        """,
        project=project,
        package=package,
    )
    return rows[0] if rows else None


# --------------------------------------------------------------------------
# Blast radius explorer — pick any package, see everything above it
# --------------------------------------------------------------------------

def blast_radius(package: str) -> dict | None:
    exists = run_query("MATCH (pkg:Package {name: $package}) RETURN pkg.name AS name", package=package)
    if not exists:
        return None

    dependent_packages = run_query(
        f"""
        MATCH (dependent:Package)-[:HAS_VERSION]->(:Version)-[:DEPENDS_ON*1..{MAX_HOPS}]->(:Package {{name: $package}})
        RETURN DISTINCT dependent.name AS package
        """,
        package=package,
    )
    exposed_projects = run_query(
        f"""
        MATCH (proj:Project)-[:REQUIRES]->(:Package)-[:HAS_VERSION]->(:Version)-[:DEPENDS_ON*0..{MAX_HOPS}]->(:Package {{name: $package}})
        RETURN DISTINCT proj.name AS project
        """,
        package=package,
    )
    return {
        "package": package,
        "dependentPackageCount": len(dependent_packages),
        "dependentPackages": [r["package"] for r in dependent_packages],
        "exposedProjectCount": len(exposed_projects),
        "exposedProjects": [r["project"] for r in exposed_projects],
    }


# --------------------------------------------------------------------------
# Maintainer concentration risk
# --------------------------------------------------------------------------

def maintainer_risk() -> list[dict]:
    return run_query(
        f"""
        MATCH (m:Maintainer)-[:MAINTAINS]->(pkg:Package)
        MATCH (proj:Project)-[:REQUIRES]->(:Package)-[:HAS_VERSION]->(:Version)-[:DEPENDS_ON*0..{MAX_HOPS}]->(pkg)
        RETURN m.name AS maintainer, m.email AS email,
               count(DISTINCT proj) AS projectsExposed,
               collect(DISTINCT pkg.name) AS packagesMaintained
        ORDER BY projectsExposed DESC
        LIMIT 15
        """
    )


# --------------------------------------------------------------------------
# Graph-shaped payloads for the visualization panel
# --------------------------------------------------------------------------

def graph_for_project(project: str) -> dict:
    # Uses run_query_raw: we need the actual Node/Path objects (labels, ids),
    # which run_query's record.data() would otherwise flatten away.
    records = run_query_raw(
        """
        MATCH (proj:Project {name: $project})
        OPTIONAL MATCH path = (proj)-[:REQUIRES]->(:Package)-[:HAS_VERSION]->(:Version)-[:DEPENDS_ON*0..3]->(:Package)
        WITH proj, collect(path) AS paths
        RETURN proj, paths
        """,
        project=project,
    )
    return _paths_to_graph(records)


def graph_for_vulnerability(cve: str) -> dict:
    records = run_query_raw(
        f"""
        MATCH (vuln:Vulnerability {{cveId: $cve}})<-[:AFFECTED_BY]-(badVersion:Version)<-[:HAS_VERSION]-(badPkg:Package)
        OPTIONAL MATCH path = (proj:Project)-[:REQUIRES]->(:Package)-[:HAS_VERSION]->(:Version)-[:DEPENDS_ON*0..{MAX_HOPS}]->(badPkg)
        WITH vuln, badPkg, collect(path) AS paths
        RETURN vuln, badPkg, paths
        """,
        cve=cve,
    )
    return _paths_to_graph(records)


def _paths_to_graph(records: list) -> dict:
    """Flatten raw neo4j Records (containing bare Nodes and/or Path objects)
    into a simple {nodes:[], edges:[]} shape the frontend's vis-network can consume."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(n):
        eid = n.element_id
        if eid not in nodes:
            label = list(n.labels)[0] if n.labels else "Node"
            display = n.get("name") or n.get("number") or n.get("cveId") or label
            nodes[eid] = {"id": eid, "label": str(display), "group": label}
        return eid

    for record in records:
        for key in record.keys():
            val = record[key]
            if key == "paths":
                for path in val or []:
                    if path is None:
                        continue
                    for node in path.nodes:
                        add_node(node)
                    for rel in path.relationships:
                        edges.append(
                            {
                                "from": add_node(rel.start_node),
                                "to": add_node(rel.end_node),
                                "label": rel.type,
                            }
                        )
            elif hasattr(val, "labels"):  # a bare node (proj, badPkg, vuln, ...)
                add_node(val)

    return {"nodes": list(nodes.values()), "edges": edges}


# --------------------------------------------------------------------------
# Write path (used only by the seed script, still fully parameterised)
# --------------------------------------------------------------------------

def wipe_database() -> None:
    run_write("MATCH (n) DETACH DELETE n RETURN count(n) AS deleted")


# NOTE on the two helpers below: Cypher's parameter binding only covers
# *values* (property values, literals) — labels and relationship types are
# part of the query's structure and the protocol has no placeholder for them,
# so every real-world Neo4j/Cypher client (including Neo4j's own docs)
# interpolates label/type names, while still parameterising every value.
# These functions are only ever called by scripts/seed.py with a small fixed
# set of labels defined in seed_data.py — never with values derived from an
# HTTP request — so there is no injection surface. All *data* (key_value,
# props) is passed as bound parameters, never string-formatted into the query.

def merge_node(label: str, key_prop: str, key_value: str, props: dict) -> None:
    run_write(
        f"MERGE (n:{label} {{{key_prop}: $key_value}}) SET n += $props RETURN n",
        key_value=key_value,
        props=props,
    )


def merge_relationship(
    from_label: str, from_key: str, from_value: str,
    rel_type: str,
    to_label: str, to_key: str, to_value: str,
    props: dict | None = None,
) -> None:
    run_write(
        f"""
        MATCH (a:{from_label} {{{from_key}: $from_value}})
        MATCH (b:{to_label} {{{to_key}: $to_value}})
        MERGE (a)-[r:{rel_type}]->(b)
        SET r += $props
        RETURN r
        """,
        from_value=from_value,
        to_value=to_value,
        props=props or {},
    )
