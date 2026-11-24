#!/usr/bin/env python3
"""Check the relative links and repository paths in the Markdown docs.

Run as `python3 -I scripts/check-docs-links.py` (stdlib and git). It reads
every tracked Markdown file except the vendored DORAM's
(machine/sidecar-oblivious/vendor), and checks two things:

- every relative Markdown link, `[text](path)` or `[text](path#anchor)`, names
  a file or directory that exists relative to the document and that git does
  not ignore, so a fresh checkout has it (http:, https: and mailto: links are
  skipped; a link to an anchor of a Markdown file must name one of its
  headings, as GitHub forms them);
- every backticked repository path, one starting `scripts/`, `e2e/`, `docs/`,
  `machine/`, `noir/`, `ts/`, `examples/`, `testvectors/` or `.github/`, exists from the repository root
  or is a path git ignores (build outputs and generated data, which a fresh
  checkout lacks). A span with a space or a placeholder (`<`, `>`, `*`, `$`,
  `{`, `...`) is not a path and is skipped; a trailing `#anchor` or
  `:<line>` is dropped.

Fenced code blocks are skipped. Exit status 0 when clean, 1 with one
`file:line: target` line per broken link or path otherwise.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDORED = "machine/sidecar-oblivious/vendor/"
PATH_ROOTS = ("scripts/", "e2e/", "docs/", "machine/", "noir/", "ts/", "examples/", "testvectors/", ".github/")
PLACEHOLDER = re.compile(r"[\s<>*${]|\.\.\.")
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
CODE_SPAN = re.compile(r"(`+)(.+?)\1")
FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
# an explicit HTML anchor, `<a id="x"></a>`, which GitHub keeps as `#x`
HTML_ANCHOR = re.compile(r'<a (?:id|name)="([^"]+)"></a>')
LINE_SUFFIX = re.compile(r"(#.*|:[\d,-]+)$")


def lines_outside_fences(path):
    """(line number, text) of every line not inside a fenced code block."""
    fence = None
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = FENCE.match(line)
        if m:
            if fence is None:
                fence = m.group(1)
            elif m.group(1) == fence:
                fence = None
            continue
        if fence is None:
            yield n, line


def anchors(path, cache={}):
    """The heading anchors GitHub gives a Markdown file."""
    if path not in cache:
        seen, out = {}, set()
        for _, line in lines_outside_fences(path):
            out.update(HTML_ANCHOR.findall(line))
            m = HEADING.match(line)
            if not m:
                continue
            text = CODE_SPAN.sub(lambda c: c.group(2), m.group(1))
            text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
            slug = re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")
            k = seen.get(slug, 0)
            seen[slug] = k + 1
            out.add(slug if k == 0 else f"{slug}-{k}")
        cache[path] = out
    return cache[path]


def git_ignored(paths):
    """The subset of `paths` (relative to the root) that git ignores, as a
    file or as a directory (a missing path could be either)."""
    if not paths:
        return set()
    out = subprocess.run(
        ["git", "-C", str(ROOT), "check-ignore", "--no-index", "--stdin"],
        input="".join(f"{p}\n{p}/\n" for p in paths), capture_output=True, text=True)
    return {p.rstrip("/") for p in out.stdout.splitlines()}


def check(doc):
    """(problem line, the missing repository path or None) per finding."""
    rel = doc.relative_to(ROOT)
    problems = []
    for n, line in lines_outside_fences(doc):
        for m in CODE_SPAN.finditer(line):
            span = m.group(2).strip()
            if not span.startswith(PATH_ROOTS) or PLACEHOLDER.search(span):
                continue
            target = LINE_SUFFIX.sub("", span).rstrip("/")
            if not (ROOT / target).exists():
                problems.append((f"{rel}:{n}: {span}", target))
        for m in LINK.finditer(CODE_SPAN.sub("", line)):
            link = m.group(1)
            if re.match(r"^(https?|mailto):", link):
                continue
            target, _, frag = link.partition("#")
            path = (doc.parent / target).resolve() if target else doc
            if not path.exists() or (path != doc and git_ignored([str(path.relative_to(ROOT))])):
                problems.append((f"{rel}:{n}: {link}", None))
            elif frag and path.suffix == ".md" and frag not in anchors(path):
                problems.append((f"{rel}:{n}: {link}", None))
    return problems


def main():
    tracked = subprocess.run(["git", "ls-files", "-z", "--", "*.md"], cwd=ROOT, capture_output=True, check=True)
    docs = [ROOT / p for p in sorted(tracked.stdout.decode().split("\0")) if p and not p.startswith(VENDORED)]
    found = [p for doc in docs for p in check(doc)]
    ignored = git_ignored(sorted({t for _, t in found if t}))
    problems = [line for line, t in found if t not in ignored]
    for p in problems:
        print(p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
