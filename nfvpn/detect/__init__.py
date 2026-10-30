"""Detection resistance: probing our own endpoint, and auditing a setup."""

from __future__ import annotations

from nfvpn.detect.audit import Audit, benchmark_backends, run_doctor
from nfvpn.detect.probe import DEFAULT_TIMEOUT, ProbeReport, format_report, probe_endpoint

__all__ = [
    "DEFAULT_TIMEOUT",
    "Audit",
    "ProbeReport",
    "benchmark_backends",
    "format_report",
    "probe_endpoint",
    "run_doctor",
]
