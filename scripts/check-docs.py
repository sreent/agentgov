#!/usr/bin/env python3
"""Check the links between the repository's Markdown files.

Every relative link must point at a file or folder that exists, and a link to a heading
(``page.md#a-heading``, or ``#a-heading`` on the same page) at a heading that exists,
with the anchors GitHub gives headings. Links to other sites aren't fetched.

  scripts/check-docs.py     exits 1, listing each broken link, if there are any
"""

from __future__ import annotations

import re
import subprocess
import sys
from functools import cache
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")


def markdown_files() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.md"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [ROOT / name for name in listed if (ROOT / name).is_file()]


def prose(path: Path) -> list[tuple[int, str]]:
    """The file's lines outside fenced code blocks, with inline code blanked."""
    lines, fenced = [], False
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            lines.append((number, re.sub(r"`[^`]*`", lambda m: " " * len(m[0]), line)))
    return lines


def slug(heading: str) -> str:
    """GitHub's anchor for a heading."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # links: their text
    text = re.sub(r"<[^>]+>", "", text).replace("`", "").lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


@cache
def anchors(path: Path) -> set[str]:
    found, seen = set(), {}
    fenced = False
    for line in path.read_text().splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        match = None if fenced else HEADING.match(line)
        if match:
            base = slug(match[2])
            count = seen.get(base, 0)
            seen[base] = count + 1
            found.add(base if count == 0 else f"{base}-{count}")
    found |= set(re.findall(r'<a\s+(?:name|id)="([^"]+)"', path.read_text()))
    return found


def broken(path: Path) -> list[str]:
    problems = []
    for number, line in prose(path):
        for target in LINK.findall(line):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target):  # https:, mailto: ...
                continue
            file, _, fragment = target.partition("#")
            where = (path.parent / unquote(file)).resolve() if file else path
            name = f"{path.relative_to(ROOT)}:{number}: {target}"
            if not where.exists():
                problems.append(f"{name} (no such file)")
            elif fragment and where.suffix == ".md" and unquote(fragment) not in anchors(where):
                problems.append(f"{name} (no such heading)")
    return problems


def main() -> int:
    problems = [p for path in markdown_files() for p in broken(path)]
    for problem in problems:
        print(problem)
    if problems:
        print(f"{len(problems)} broken link(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
