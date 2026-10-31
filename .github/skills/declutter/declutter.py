#!/usr/bin/env python3
"""Find and remove mechanical clutter in a git repository.

  declutter.py scan           report banners, emoji, allow(dead_code), stale claims
  declutter.py banners --fix  delete '// ====' rule lines in .rs files, keep titles
  declutter.py emoji --fix    strip emoji from tracked text files

Only tracked files are touched. Run `cargo fmt --all` afterwards. Judgment
calls (dead code, false claims, rewrites) stay with the person running this.
"""
import re
import subprocess
import sys

EMOJI = re.compile("[\U0001F300-\U0001FAFF✅❌⚠✨⭐✔✖❤]️?")
RULE = re.compile(r"^(\s*)//\s*[=\-]{8,}\s*$")
TITLE = re.compile(r"^\s*//(?!\s*[=\-]{8,}\s*$)(?![/!])")
TEXT = (".md", ".rs", ".py", ".toml", ".yml", ".yaml", ".sh")
CLAIMS = re.compile(
    r"production[- ]ready|100% complete|enterprise-grade|battle-tested|world-class",
    re.I,
)


def tracked(*suffixes):
    out = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
    return [f for f in out if f.endswith(suffixes or TEXT)]


def read(path):
    try:
        with open(path, encoding="utf8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def strip_banners(text):
    """Drop rule lines. A rule, up to 3 title lines, then a rule keeps the titles."""
    lines, out, i, removed = text.split("\n"), [], 0, 0
    while i < len(lines):
        if RULE.match(lines[i]):
            j, titles = i + 1, []
            while j < len(lines) and TITLE.match(lines[j]) and len(titles) < 3:
                titles.append(lines[j])
                j += 1
            if titles and j < len(lines) and RULE.match(lines[j]):
                out.extend(titles)
                removed += 2
                i = j + 1
                continue
            removed += 1
            i += 1
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out), removed


def strip_emoji(text):
    # A table cell holding only a marker becomes "Done"; elsewhere the marker goes.
    text = re.sub(r"\|\s*" + EMOJI.pattern + r"\s*\|", "| Done |", text)
    text = re.sub(r" " + EMOJI.pattern + r"\s*$", "", text, flags=re.M)
    return re.sub(EMOJI.pattern + r"[ \t]*", "", text)


def scan():
    banners = emoji = dead = 0
    for f in tracked():
        t = read(f)
        if t is None:
            continue
        for n, line in enumerate(t.split("\n"), 1):
            if f.endswith(".rs") and RULE.match(line):
                banners += 1
            if EMOJI.search(line):
                emoji += 1
                print(f"emoji  {f}:{n}: {line.strip()[:80]}")
            if f.endswith(".rs") and "allow(dead_code)" in line:
                dead += 1
                print(f"dead?  {f}:{n}")
            if f.endswith(".md") and CLAIMS.search(line):
                print(f"claim  {f}:{n}: {line.strip()[:80]}")
    print(f"\n{banners} banner lines, {emoji} lines with emoji, {dead} allow(dead_code)")


def fix(kind):
    changed = 0
    for f in tracked(".rs") if kind == "banners" else tracked():
        t = read(f)
        if t is None:
            continue
        new = strip_banners(t)[0] if kind == "banners" else strip_emoji(t)
        if new != t:
            with open(f, "w", encoding="utf8") as fh:
                fh.write(new)
            changed += 1
    print(f"{kind}: {changed} files changed")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["scan"]:
        scan()
    elif len(args) == 2 and args[0] in ("banners", "emoji") and args[1] == "--fix":
        fix(args[0])
    else:
        sys.exit(__doc__)
