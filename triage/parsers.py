"""Parse dependency manifests into a flat list of (ecosystem, name, version).

Supported inputs:
  * requirements.txt  -> PyPI
  * package.json      -> npm

A dependency whose exact version cannot be determined (e.g. ``flask>=1.0`` or
``"lodash": "*"``) is still returned, with ``version=None`` and a note, so the
report can flag it for human review instead of guessing a version.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# PEP 503 name normalisation.
_NORMALIZE_RE = re.compile(r"[-_.]+")
# name[extras] <op> version
_REQ_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?P<spec>[^;#]*)"
)
_NPM_EXACT_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")
_NPM_FLOOR_RE = re.compile(r"^(?:\^|~|>=|=)\s*v?(\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?)$")


@dataclass
class Dependency:
    ecosystem: str  # "PyPI" | "npm"
    name: str
    version: str | None
    raw: str
    note: str | None = None
    dev: bool = False

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass
class ParseResult:
    ecosystem: str
    dependencies: list[Dependency] = field(default_factory=list)

    @property
    def resolved(self) -> list[Dependency]:
        return [d for d in self.dependencies if d.version]

    @property
    def unresolved(self) -> list[Dependency]:
        return [d for d in self.dependencies if not d.version]


def normalize_pypi_name(name: str) -> str:
    return _NORMALIZE_RE.sub("-", name).lower()


def detect_format(filename: str, content: str) -> str:
    """Return "requirements" or "package.json"."""
    lower = filename.lower()
    if lower.endswith(".json"):
        return "package.json"
    if lower.endswith(".txt") or lower.endswith(".in"):
        return "requirements"
    stripped = content.lstrip()
    return "package.json" if stripped.startswith("{") else "requirements"


def parse_requirements(content: str) -> ParseResult:
    result = ParseResult(ecosystem="PyPI")
    seen: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        # Handle line continuations and hash pins loosely: drop everything after " \\" or "--hash".
        line = line.split(" --hash")[0].rstrip("\\").strip()
        if not line or line.startswith("#") or line.startswith("-"):
            # comments, -r/-e/-c/--index-url options
            continue
        if "://" in line or line.startswith((".", "/")):
            continue  # direct URL / local path installs have no registry version
        m = _REQ_RE.match(line)
        if not m:
            continue
        name = normalize_pypi_name(m.group("name"))
        if name in seen:
            continue
        seen.add(name)
        spec = m.group("spec").strip().replace(" ", "")
        version: str | None = None
        note: str | None = None
        if spec.startswith("===") or spec.startswith("=="):
            candidate = spec.lstrip("=").split(",")[0]
            if "*" in candidate:
                note = f"wildcard pin '{spec}' - exact version unknown"
            else:
                version = candidate
        elif not spec:
            note = "unpinned - exact version unknown"
        else:
            note = f"range '{spec}' - exact version unknown (pin it or supply a lock file)"
        result.dependencies.append(
            Dependency(ecosystem="PyPI", name=name, version=version, raw=line, note=note)
        )
    return result


def parse_package_json(content: str) -> ParseResult:
    result = ParseResult(ecosystem="npm")
    data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError("package.json must be a JSON object")
    for section, dev in (("dependencies", False), ("devDependencies", True)):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            spec_s = str(spec).strip()
            version: str | None = None
            note: str | None = None
            exact = _NPM_EXACT_RE.match(spec_s)
            floor = _NPM_FLOOR_RE.match(spec_s)
            if exact:
                version = exact.group(1)
            elif floor:
                version = _pad_semver(floor.group(1))
                note = (
                    f"range '{spec_s}' - using the lowest allowed version {version}; "
                    "a lock file would give the exact installed version"
                )
            else:
                note = f"unsupported spec '{spec_s}' - exact version unknown"
            result.dependencies.append(
                Dependency(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    raw=f"{name}@{spec_s}",
                    note=note,
                    dev=dev,
                )
            )
    return result


def _pad_semver(v: str) -> str:
    core, sep, pre = v.partition("-")
    parts = core.split(".")
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts) + (sep + pre if sep else "")


def parse_manifest(filename: str, content: str) -> ParseResult:
    fmt = detect_format(filename, content)
    if fmt == "package.json":
        return parse_package_json(content)
    return parse_requirements(content)
