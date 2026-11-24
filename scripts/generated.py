"""Where a generator's files go: written, or with --check compared with the
committed files, for the examples' gen-fixtures.py. A generator passes every
file it makes through `Output.write` and ends with `Output.finish`, which in
check mode fails naming each file that differs, is missing, or matches one of
the generator's patterns without being generated (a case the generator no
longer writes).

    python3 -I examples/<example>/circuits/gen-fixtures.py           # write
    python3 -I examples/<example>/circuits/gen-fixtures.py --check   # compare
"""

import glob
import os
import sys


class Output:
    def __init__(self, argv, root, patterns):
        """`argv` the generator's arguments (nothing, or --check), `root` the
        directory the paths are reported against, `patterns` the globs under
        `root` that hold only generated files."""
        unknown = [a for a in argv if a != "--check"]
        if unknown:
            sys.exit(f"usage: {os.path.basename(sys.argv[0])} [--check] (not {' '.join(unknown)})")
        self.check = "--check" in argv
        self.root = root
        self.patterns = patterns
        self.made = set()
        self.stale = []

    def write(self, path, text):
        path = os.path.abspath(path)
        self.made.add(path)
        if not self.check:
            with open(path, "w") as f:
                f.write(text)
            return
        try:
            with open(path) as f:
                same = f.read() == text
        except FileNotFoundError:
            same = False
        if not same:
            self.stale.append(f"{os.path.relpath(path, self.root)}: differs from the generator's output, or is missing")

    def finish(self, what):
        """In check mode, exits 1 naming every stale file; `what` names the
        generated set in the verdict."""
        if not self.check:
            return
        for pattern in self.patterns:
            for path in sorted(glob.glob(os.path.join(self.root, pattern))):
                if os.path.abspath(path) not in self.made:
                    self.stale.append(f"{os.path.relpath(path, self.root)}: not written by the generator")
        if self.stale:
            print("\n".join(self.stale), file=sys.stderr)
            sys.exit(f"{what}: {len(self.stale)} stale file(s); rerun {os.path.basename(sys.argv[0])} without --check")
        print(f"{what}: {len(self.made)} files current", file=sys.stderr)
