#!/usr/bin/env python3
import argparse
import os
import pathlib
import re
import sys

PATTERN = re.compile(r"@@([A-Z0-9_]+)@@")

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("template")
    p.add_argument("output")
    args = p.parse_args()

    text = pathlib.Path(args.template).read_text()
    missing = sorted({m.group(1) for m in PATTERN.finditer(text) if m.group(1) not in os.environ})
    if missing:
        print("missing template variables: " + ", ".join(missing), file=sys.stderr)
        return 2

    text = PATTERN.sub(lambda m: os.environ[m.group(1)], text)
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name("." + out.name + ".tmp")
    tmp.write_text(text)
    os.chmod(tmp, 0o600)
    tmp.replace(out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
