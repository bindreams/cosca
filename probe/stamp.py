"""Prefix every line with a UTC timestamp as it arrives (live evidence). Usage: cmd | python3 -u stamp.py"""
import sys, datetime
for raw in iter(sys.stdin.buffer.readline, b""):  # one line at a time: no read-ahead buffering
    sys.stdout.write(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ ") + raw.decode(errors="replace"))
    sys.stdout.flush()
