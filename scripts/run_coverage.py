#!/usr/bin/env python
"""
ForensiQ Automated Test Coverage Runner
Executes Django unit tests and comprehensive E2E workstation suites under coverage.py,
generates detailed terminal reports, and produces interactive HTML coverage dashboards.
"""

import argparse
import subprocess  # nosec B404
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def print_banner(text: str) -> None:
    line = "=" * 70
    print(f"\n{line}\n  {text}\n{line}")


def run_command(cmd: list[str], description: str) -> bool:
    print(f"\n[Coverage Runner] >> {description}...")
    try:
        res = subprocess.run(cmd, cwd=str(BASE_DIR), check=True)  # nosec B603
        return res.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"\n[FAIL] Step failed with return code {e.returncode}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Run ForensiQ test suite under code coverage.")
    parser.add_argument(
        "--include-e2e",
        action="store_true",
        default=True,
        help="Include comprehensive 10-phase Master E2E suite in coverage measurement (default: True)",
    )
    parser.add_argument(
        "--unit-only",
        action="store_true",
        help="Run only Django unit tests without E2E workstation suite",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        default=True,
        help="Generate interactive HTML report in htmlcov/index.html (default: True)",
    )
    parser.add_argument(
        "--fail-under",
        type=int,
        default=60,
        help="Minimum required coverage percentage (default: 60%%)",
    )
    args = parser.parse_args()

    print_banner("FORENSIQ AUTOMATED TEST COVERAGE ENGINE")

    # Step 1: Run Django unit tests under coverage
    unit_ok = run_command(
        ["uv", "run", "coverage", "run", "manage.py", "test"],
        "Executing Django Unit Test Suite (283 tests)",
    )
    if not unit_ok:
        sys.exit(1)

    # Step 2: Optionally run Master E2E and Feature Verification suites under coverage append
    if args.include_e2e and not args.unit_only:
        run_command(
            ["uv", "run", "python", "manage.py", "migrate", "--noinput"],
            "Initializing Database Schema for Workstation E2E Suite",
        )
        e2e_ok = run_command(
            [
                "uv",
                "run",
                "coverage",
                "run",
                "--append",
                "scripts/test_e2e_workstation.py",
            ],
            "Executing Master 12-Phase End-to-End Suite (--append)",
        )
        if not e2e_ok:
            sys.exit(1)

        verify_ok = run_command(
            [
                "uv",
                "run",
                "coverage",
                "run",
                "--append",
                "scripts/verify_all_features.py",
            ],
            "Executing Systematic Feature Verification Suite (--append)",
        )
        if not verify_ok:
            sys.exit(1)

    # Step 3: Print terminal coverage report
    print_banner("TEST COVERAGE REPORT SUMMARY")
    report_cmd = ["uv", "run", "coverage", "report"]
    if args.fail_under:
        report_cmd.extend(["--fail-under", str(args.fail_under)])
    report_ok = run_command(report_cmd, "Compiling Module-by-Module Coverage Report")

    # Step 4: Generate HTML report
    if args.html:
        html_ok = run_command(
            ["uv", "run", "coverage", "html"],
            "Generating Interactive HTML Report (htmlcov/index.html)",
        )
        if html_ok:
            print(
                "\n[OK] Interactive HTML Coverage Dashboard: file://"
                + str(BASE_DIR / "htmlcov" / "index.html")
            )

    if not report_ok:
        print(f"\n[FAIL] Coverage fell below minimum required threshold of {args.fail_under}%.")
        sys.exit(1)

    print(
        "\n[SUCCESS] Test suite executed under coverage with 100% passing tests and verified quality gates!\n"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
