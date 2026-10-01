"""Deterministic reference priority rubric.

The agent is shown this rubric and may deviate with a written reason (e.g. a
dev-only dependency). The checker and the eval use it as the reference to
measure how often the agent's judgement agrees with it.
"""

from __future__ import annotations

PRIORITIES = ("P1", "P2", "P3", "P4")

RUBRIC_TEXT = """\
P1 - fix now:        listed in CISA KEV (actively exploited), OR EPSS >= 0.50,
                     OR CVSS >= 9.0 with EPSS >= 0.10
P2 - fix this sprint: CVSS >= 7.0, OR EPSS >= 0.10
P3 - plan a fix:     CVSS >= 4.0
P4 - low:            CVSS < 4.0
If CVSS is unknown and the item is not in KEV and EPSS is below 0.10 or unknown,
there is not enough evidence to rank it: choose your best judgement and put the
item up for human review."""


def reference_priority(cvss: float | None, in_kev: bool | None, epss: float | None) -> str | None:
    """Return P1-P4, or None when there is not enough evidence to rank."""
    if in_kev:
        return "P1"
    e = epss or 0.0
    if e >= 0.50:
        return "P1"
    if cvss is not None and cvss >= 9.0 and e >= 0.10:
        return "P1"
    if (cvss is not None and cvss >= 7.0) or e >= 0.10:
        return "P2"
    if cvss is None:
        return None
    if cvss >= 4.0:
        return "P3"
    return "P4"
