#!/usr/bin/env python3
"""Fail CI on called vulnerabilities that are not explicitly accepted.

Reads `govulncheck -format json` output on stdin. A finding counts only when
its trace reaches a function (the code is called), matching govulncheck's own
text-mode exit status. Accepted IDs live in .govulncheck-allow.json, each with
a reason and a review date; an entry past its review date fails the gate so an
exception cannot be forgotten.
"""
import datetime
import json
import sys
from pathlib import Path

ALLOW = Path(__file__).resolve().parent.parent / ".govulncheck-allow.json"


def findings(stream):
    called, decoder, buf = set(), json.JSONDecoder(), stream.read()
    i = 0
    while i < len(buf):
        while i < len(buf) and buf[i].isspace():
            i += 1
        if i >= len(buf):
            break
        obj, i = decoder.raw_decode(buf, i)
        f = obj.get("finding")
        if f and any(frame.get("function") for frame in f.get("trace", [])):
            called.add(f["osv"])
    return called


def main():
    today = datetime.date.today()
    entries = json.loads(ALLOW.read_text(encoding="utf-8")) if ALLOW.exists() else []
    allowed, problems = {}, []
    for e in entries:
        if not e.get("id") or not e.get("reason") or not e.get("review_by"):
            problems.append("allowlist entry needs id, reason and review_by: %r" % e)
            continue
        if datetime.date.fromisoformat(e["review_by"]) < today:
            problems.append("%s: review date %s has passed; re-check and extend or remove" % (e["id"], e["review_by"]))
        allowed[e["id"]] = e
    called = findings(sys.stdin)
    for osv in sorted(called):
        if osv in allowed:
            print("accepted %s: %s (review by %s)" % (osv, allowed[osv]["reason"], allowed[osv]["review_by"]))
        else:
            problems.append("called vulnerability %s is not accepted" % osv)
    for osv in sorted(set(allowed) - called):
        print("note: %s is no longer reported; remove it from %s" % (osv, ALLOW.name))
    for p in problems:
        print("ERROR: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
