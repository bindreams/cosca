#!/usr/bin/env python3
"""Fails unless a nextest JUnit file holds exactly N tests, none skipped, failed or errored.

    check-junit.py <junit.xml> --tests N

nextest leaves ignored tests out of the JUnit file unless the profile sets `junit.report-skipped = "ignored"`
(the `ci-elevation` profile does); with that, an ignored test is a skipped one here, so a lane whose tests went
ignored fails on the count and on the skipped check.
"""

import argparse
import sys
import xml.etree.ElementTree as ElementTree


def check(path, expected):
    cases = ElementTree.parse(path).getroot().findall(".//testcase")
    skipped = [case for case in cases if case.find("skipped") is not None]
    failed = [case for case in cases if case.find("failure") is not None or case.find("error") is not None]
    problems = []
    if len(cases) != expected:
        problems.append(f"{len(cases)} tests, expected exactly {expected}")
    if skipped:
        problems.append(f"{len(skipped)} skipped: {[case.get('name') for case in skipped]}")
    if failed:
        problems.append(f"{len(failed)} failed: {[case.get('name') for case in failed]}")
    return problems


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit")
    parser.add_argument("--tests", type=int, required=True)
    args = parser.parse_args(argv)
    problems = check(args.junit, args.tests)
    for problem in problems:
        print(f"::error::{args.junit}: {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
