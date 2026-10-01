import json

import pytest

from triage.parsers import detect_format, parse_manifest, parse_package_json, parse_requirements


def test_requirements_pins_ranges_and_noise():
    content = """
# comment
Jinja2==2.10
requests[security]==2.19.1 ; python_version >= "3.6"
Flask>=1.0
pyyaml
django==2.2.*
-r other.txt
--index-url https://example.com
git+https://github.com/x/y.git
urllib3==1.24.1 --hash=sha256:abc
jinja2==3.0   # duplicate, first one wins
"""
    r = parse_requirements(content)
    by = {d.name: d for d in r.dependencies}
    assert r.ecosystem == "PyPI"
    assert by["jinja2"].version == "2.10"
    assert by["requests"].version == "2.19.1"
    assert by["urllib3"].version == "1.24.1"
    assert by["flask"].version is None and "range" in by["flask"].note
    assert by["pyyaml"].version is None and "unpinned" in by["pyyaml"].note
    assert by["django"].version is None and "wildcard" in by["django"].note
    assert len(r.dependencies) == 6
    assert {d.name for d in r.unresolved} == {"flask", "pyyaml", "django"}


def test_package_json_exact_caret_and_unsupported():
    pj = {
        "name": "x",
        "dependencies": {"lodash": "4.17.4", "express": "^4.16.0", "left-pad": "*", "mylib": "file:../mylib"},
        "devDependencies": {"minimist": "~1.2", "jquery": "v3.4.0"},
    }
    r = parse_package_json(json.dumps(pj))
    by = {d.name: d for d in r.dependencies}
    assert by["lodash"].version == "4.17.4" and by["lodash"].note is None
    assert by["express"].version == "4.16.0" and "lowest allowed" in by["express"].note
    assert by["minimist"].version == "1.2.0" and by["minimist"].dev
    assert by["jquery"].version == "3.4.0"
    assert by["left-pad"].version is None
    assert by["mylib"].version is None


def test_detect_format():
    assert detect_format("package.json", "{}") == "package.json"
    assert detect_format("requirements.txt", "a==1") == "requirements"
    assert detect_format("upload", '  {"dependencies": {}}') == "package.json"
    assert parse_manifest("reqs.txt", "a==1").ecosystem == "PyPI"


def test_bad_package_json():
    with pytest.raises(ValueError):
        parse_package_json("[]")
