"""Fail-closed fixtures for both independently scoped Hickory advisory exceptions."""

from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("check_cargo_dnssec", Path(__file__).with_name("check-cargo-dnssec.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def metadata():
    packages = [
        {"id": name, "name": name, "version": version, "source": checker.REGISTRY}
        for name, version in [*checker.REVIEWED.items(), ("reqwest", "0.12.28")]
    ]
    nodes = [
        {"id": name, "features": features, "deps": [{"pkg": dependency} for dependency in dependencies]}
        for name, features, dependencies in [
            ("reqwest", ["hickory-dns"], ["hickory-resolver"]),
            ("hickory-resolver", ["tokio"], ["hickory-proto"]),
            ("hickory-proto", ["tokio"], []),
        ]
    ]
    return {"packages": packages, "resolve": {"nodes": nodes}}


def test_reviewed_stub_graph_success():
    """The reviewed registry stub path and DNSSEC-free graph remain permitted."""
    checker.check_metadata(metadata())


@pytest.mark.parametrize("variant", [
    "recursor", "resolver-version", "resolver-source", "proto-version", "proto-dnssec", "resolver-dnssec",
    "client-version", "client-source", "client-name", "new-caller", "orphan-resolver", "disabled-client",
])
def test_boundary_drift_failure(variant):
    """Package, source, caller and feature changes require reassessment before suppression."""
    candidate = deepcopy(metadata())
    packages = {package["name"]: package for package in candidate["packages"]}
    nodes = {node["id"]: node for node in candidate["resolve"]["nodes"]}
    if variant == "recursor":
        candidate["packages"].append({"id": "recursor", "name": "hickory-recursor", "version": "0.25.2", "source": checker.REGISTRY})
    elif variant == "resolver-version":
        packages["hickory-resolver"]["version"] = "0.26.3"
    elif variant == "resolver-source":
        packages["hickory-resolver"]["source"] = "git+https://example.invalid/fork"
    elif variant == "proto-version":
        packages["hickory-proto"]["version"] = "0.26.3"
    elif variant == "proto-dnssec":
        nodes["hickory-proto"]["features"].append("dnssec-ring")
    elif variant == "resolver-dnssec":
        nodes["hickory-resolver"]["features"].append("dnssec-ring")
    elif variant == "client-version":
        packages["reqwest"]["version"] = "0.13.5"
    elif variant == "client-source":
        packages["reqwest"]["source"] = None
    elif variant == "client-name":
        packages["reqwest"]["name"] = "other-resolver-user"
    elif variant == "new-caller":
        candidate["packages"].append({"id": "other", "name": "other", "version": "1.0.0"})
        candidate["resolve"]["nodes"].append({"id": "other", "features": [], "deps": [{"pkg": "hickory-resolver"}]})
    elif variant == "orphan-resolver":
        nodes["reqwest"]["deps"] = []
    elif variant == "disabled-client":
        nodes["reqwest"]["features"] = []
    with pytest.raises(ValueError):
        checker.check_metadata(candidate)


def test_unselected_recursor_lock_entry_failure():
    """Even an unselected platform or optional recursor package invalidates the exception."""
    packages = metadata()["packages"]
    packages.append({"name": "hickory-recursor", "version": "0.25.2"})
    with pytest.raises(ValueError, match="hickory-recursor absent"):
        checker.check_packages(packages)
