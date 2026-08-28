"""
Thin wrapper around the official Neo4j Python driver, pointed at CognoDB
(which speaks openCypher over Bolt 5.x, so the stock driver works unmodified).

Design goals:
  - one driver instance for the app's lifetime (the driver is already a
    connection pool, so we don't want to create one per-request)
  - never let a database outage crash the process or leak a stack trace to
    the client — callers get a DatabaseUnavailableError they can turn into
    a clean 503
  - every query is parameterised; nothing here ever f-strings user input
    into Cypher
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable, AuthError, Neo4jError

from app.config import settings


class DatabaseUnavailableError(RuntimeError):
    """Raised whenever CognoDB cannot be reached or a query fails at the driver level."""


_driver: Driver | None = None


def get_driver() -> Driver:
    global _driver
    if not settings.is_configured:
        raise DatabaseUnavailableError(
            "CognoDB connection is not configured. Set COGNODB_URI, COGNODB_USER "
            "and COGNODB_PASSWORD (see .env.example)."
        )
    if _driver is None:
        try:
            _driver = GraphDatabase.driver(
                settings.cognodb_uri,
                auth=(settings.cognodb_user, settings.cognodb_password),
            )
        except Exception as exc:  # driver construction rarely fails, but be safe
            raise DatabaseUnavailableError(f"Could not initialise CognoDB driver: {exc}") from exc
    return _driver


def verify_connectivity() -> tuple[bool, str]:
    """Used by /api/health. Returns (ok, message)."""
    try:
        driver = get_driver()
        driver.verify_connectivity()
        return True, "connected"
    except DatabaseUnavailableError as exc:
        return False, str(exc)
    except AuthError:
        return False, "Authentication to CognoDB failed — check COGNODB_USER/COGNODB_PASSWORD."
    except ServiceUnavailable:
        return False, "CognoDB is unreachable — check COGNODB_URI and that the instance is running."
    except Exception as exc:  # noqa: BLE001 - surface anything unexpected as a clean message
        return False, f"Unexpected error contacting CognoDB: {exc}"


@contextmanager
def session() -> Iterator[Any]:
    driver = get_driver()
    try:
        with driver.session(database=settings.cognodb_database) as sess:
            yield sess
    except AuthError as exc:
        raise DatabaseUnavailableError(
            "Authentication to CognoDB failed — check COGNODB_USER/COGNODB_PASSWORD."
        ) from exc
    except ServiceUnavailable as exc:
        raise DatabaseUnavailableError(
            "CognoDB is unreachable — check COGNODB_URI and that the instance is running."
        ) from exc
    except Neo4jError as exc:
        raise DatabaseUnavailableError(f"CognoDB query failed: {exc.message}") from exc


def run_query(query: str, **params: Any) -> list[dict[str, Any]]:
    """Run a single parameterised Cypher query and return a list of plain dicts.
    Use this for everything except graph-shaped (Node/Path) results — record.data()
    recursively flattens Nodes/Paths down to their bare properties, which is exactly
    what we want for JSON API responses but would strip the labels/ids the graph
    visualization endpoints need. Use run_query_raw for those instead."""
    with session() as sess:
        result = sess.run(query, **params)
        return [record.data() for record in result]


def run_query_raw(query: str, **params: Any) -> list[Any]:
    """Run a parameterised Cypher query and return raw driver Records, preserving
    Node/Relationship/Path objects (labels, element_id, .nodes/.relationships) intact.
    Only used by the graph-visualization endpoints, which need that structure."""
    with session() as sess:
        result = sess.run(query, **params)
        return list(result)


def run_write(query: str, **params: Any) -> list[dict[str, Any]]:
    """Run a parameterised write query inside an explicit write transaction."""
    with session() as sess:
        return sess.execute_write(lambda tx: [r.data() for r in tx.run(query, **params)])


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
