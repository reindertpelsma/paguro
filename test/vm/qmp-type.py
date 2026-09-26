#!/usr/bin/env python3
"""QMP send-key commands (one JSON per line) that type text or press key
combos — for guests reached only through a QMP socket inside L2, where
`paguro-vm qmp` sends them (nested-e2e.sh). US layout, ASCII.

    qmp-type.py --text 'cmd /k ver' [--enter]
    qmp-type.py --combo meta_l-r
"""
import json
import sys

PLAIN = {" ": "spc", "\n": "ret", "\t": "tab", "-": "minus", "=": "equal", "[": "bracket_left",
         "]": "bracket_right", "\\": "backslash", ";": "semicolon", "'": "apostrophe",
         "`": "grave_accent", ",": "comma", ".": "dot", "/": "slash"}
SHIFTED = {"!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7", "*": "8",
           "(": "9", ")": "0", "_": "minus", "+": "equal", "{": "bracket_left",
           "}": "bracket_right", "|": "backslash", ":": "semicolon", '"': "apostrophe",
           "~": "grave_accent", "<": "comma", ">": "dot", "?": "slash"}


def keys(c):
    if c.isascii() and c.isalpha():
        return ["shift", c.lower()] if c.isupper() else [c]
    if c.isascii() and c.isdigit():
        return [c]
    if c in PLAIN:
        return [PLAIN[c]]
    if c in SHIFTED:
        return ["shift", SHIFTED[c]]
    sys.exit(f"cannot type {c!r}")


def cmd(ks):
    return json.dumps({"execute": "send-key", "arguments": {
        "keys": [{"type": "qcode", "data": k} for k in ks], "hold-time": 60}})


a = sys.argv[1:]
if a[0] == "--text":
    for c in a[1]:
        print(cmd(keys(c)))
    if "--enter" in a:
        print(cmd(["ret"]))
elif a[0] == "--combo":
    print(cmd(a[1].split("-")))
