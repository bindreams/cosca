#!/usr/bin/env python3
"""THROWAWAY (PR #377): runs argv in a new session, so its process group is orphaned (H1)."""
import os, sys
os.setsid()
os.execvp(sys.argv[1], sys.argv[1:])
