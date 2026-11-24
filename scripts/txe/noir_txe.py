#!/usr/bin/env python3
"""Run Aztec contract tests (TestEnvironment / TXE) in a fresh copied workspace.

Run it through scripts/txe.sh, which sources scripts/toolchain.sh: the runner
reads CONTRACT_NARGO_BIN and BB_BIN (and their pinned versions) from the
environment and refuses tools that report another version. The only profile is
hosted-v6 (nargo 1.0.0-rc.3, bb 6.0.0, @aztec-labs/txe 6.0.0); a config names it
as "txe_profile". The runner provisions no tool and no key.

Package paths in a config are relative to the repository root, wherever the
config file lives. The listed packages and their local path dependencies inside
the repository are copied into .runs/txe/<id>/workspace at the same relative
paths. Dependencies reached through deps/ (the Aztec source worlds that
scripts/bootstrap.sh links) are not copied: the workspace holds a `deps`
symlink to the repository's deps/ at the same relative depth, so every relative
path in the copied Nargo.toml files resolves unchanged, and aztec-nr's own
relative paths between the two worlds still resolve inside deps/.

--contracts explicitly enables contract compilation and verification-key generation.
Packages listed under "keyless_contracts" must have no private or public function.
They are compiled and marked transpiled by `bb aztec_process`, which then has no
public bytecode to transpile and no verification key to generate, so it reads no SRS.
The runner checks both conditions. Local path dependencies that the config does not
list are staged too (Nargo.toml and src/ only), but only listed packages are tested.
No proof, network deployment, or source-repository build is performed.

"exclude_test_modules" lists test modules (such as contract_test, or a nested
`test::constrained`) that the "packages" runs leave out; "include_test_modules"
lists the only modules they run. A module matches itself and all that it
contains. "exclude_tests" lists full test names that the runs leave out (a
known failing test). The runner lists each package's tests with
`nargo test --list-tests` and runs the selected ones by exact name; an include
list that selects no test is an error.

Parallelism. The runner starts one TXE server per run. It builds the deployed
contracts side by side and runs the listed packages' `nargo test` side by side
("package_jobs", default: all of them at once), and each `nargo test` runs
"test_threads" tests at a time (default 8). Every test is its own TXE session:
nargo gives each test a fresh session id, and the TXE routes each session to
one of its worker threads (at most 16, the TXE's own cap) with its own world
state and stores, so tests never share chain state and their order does not
matter. The cost of more threads is memory in the one TXE process (each live
session holds a world state) and CPU. The environment variables
TXE_TEST_THREADS and TXE_PACKAGE_JOBS override the config (1 and 1 run
everything serially). null for "test_threads" leaves nargo's default (one per
core).

"deployed_contracts" lists contract packages that the library test packages
deploy (a test that calls `env.deploy("../gate@gate/Gate")` reads
`../gate/target/gate-Gate.json`). With `--contracts`, the runner compiles each
one in the copied workspace and runs `bb aztec_process` on its artifacts (which
generates verification keys and reads the SRS) before the first `nargo test`,
so the artifacts exist when the tests deploy them. The entry is a path or an
object {"path", "compiler_flags", "timeout_seconds", "keygen_timeout_seconds",
"artifact", "artifact_name"} with the meaning below. Without `--contracts` the
runner refuses a config that lists deployed contracts, so key generation is
never implicit.

A "contracts" entry is a path or an object {"path", "compiler_flags",
"timeout_seconds" (compile), "keygen_timeout_seconds", "test_timeout_seconds",
"test_filter", "artifact", "artifact_name"}. The object form lets a contract
compile with its own inliner setting (so the class id matches its retained
parity build) and run only the tests whose name contains the filter. With
"artifact" (an absolute path to a compiled, unprocessed contract artifact that
the caller produced from the same source and flags), the runner copies it to
target/<artifact_name> instead of compiling the contract again. The report records, for each contract,
the stripped-artifact digest (no file_map, debug_symbols or function hash)
that bytecode-parity checks compare, and time and peak RSS of each command;
"tests_passed", "seconds" and "peak_rss_kib" summarize the run. Package runs use
nargo's JSON report, so each "tests-<i>" command also lists every test with its
own seconds, slowest first: where a suite's time goes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import selectors
import secrets
import subprocess
import tempfile
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[2]
TXE_DIR = Path(__file__).resolve().parent
# Files in scripts/txe that start the TXE server.
TXE_LAUNCHER = ("serve.mjs", "session_keepalive.mjs")
# The gitignored links to the Aztec source worlds, made by scripts/bootstrap.sh.
DEPS = "deps"

# The TXE profile. "hosted-v6" is the only one: contract nargo 1.0.0-rc.3
# (CONTRACT_NARGO_BIN) and bb 6.0.0 (BB_BIN), the versions scripts/toolchain.sh
# pins, with @aztec-labs/txe 6.0.0 from scripts/txe/package.json. aztec-nr
# v6.0.0 is released for that compiler and the TXE executes its oracle calls;
# another nargo, bb or TXE version produces artifacts, keys or oracle
# behaviour the v6 contracts were not tested with. Moving to another Aztec
# release means moving all three together (and the deps/ worlds), then adding
# a profile name here so older configs fail loudly instead of running on it.
PROFILES = {
    "hosted-v6": {
        "CONTRACT_NARGO_BIN": "CONTRACT_NARGO_VERSION",
        "BB_BIN": "BB_VERSION",
    },
}

# Where run directories go and how many are kept. Each run writes
# .runs/txe/<time_ns>/ in the repository (gitignored): the copied workspace
# with its compiled contracts, one log per command, and report.json. The runner
# deletes the oldest runs at the start of a run so that at most TXE_KEEP_RUNS
# (default 3) remain afterwards, counting the new one. Raise it to keep more
# evidence; 1 keeps only the latest run. Nothing outside .runs/txe is deleted.
RUNS = ROOT / ".runs" / "txe"
KEEP_RUNS = int(os.environ.get("TXE_KEEP_RUNS", "3"))

# Where the scratch files of nargo, bb and the TXE server go: a per-run
# directory under TXE_TMP_ROOT (default .runs/tmp in this repository), passed
# to every child as TMPDIR and removed when the run ends, so nothing lands in
# the system temp directory. The root must stay short: the TXE server and the
# world-state process bind Unix sockets under TMPDIR, and a socket path is
# limited to 107 bytes. Moving the root changes where scratch directories
# appear and nothing else, as long as the path stays short.
TMP_ROOT = Path(os.environ.get("TXE_TMP_ROOT") or ROOT / ".runs" / "tmp")

# Tests at a time in each package's `nargo test` (each test one TXE session)
# when the config names no "test_threads". Eight keep a run's TXE process to
# roughly the memory of eight live sessions; TXE_TEST_THREADS overrides both.
DEFAULT_TEST_THREADS = 8


def positive_or_none(value, name):
    """`value` if it is a positive integer or None, else exit naming `name`."""
    if value is not None and (
        not isinstance(value, int) or isinstance(value, bool) or value < 1
    ):
        raise SystemExit(f"{name} must be a positive integer or null")
    return value


def env_int(name):
    """The positive integer in environment variable `name`, or None if unset."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return None
    try:
        return positive_or_none(int(raw), name)
    except ValueError:
        raise SystemExit(f"{name} must be a positive integer") from None


def test_events(text):
    """The per-test results of a `nargo test --format json` log: name, event
    ("ok", "failed", "ignored"), seconds and, for a failure, its output. Lines
    that are not JSON test events (compiler warnings) are skipped."""
    tests = []
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("type") != "test" or record.get("event") == "started":
            continue
        test = {
            "name": record.get("name"),
            "event": record.get("event"),
            "seconds": round(float(record.get("exec_time") or 0), 3),
        }
        if record.get("event") == "failed":
            test["output"] = record.get("stdout") or record.get("message") or ""
        tests.append(test)
    return tests


def run_all(jobs, function, items):
    """Call `function(i, item)` for every item, `jobs` at a time, wait for all
    of them, and re-raise the first failure (in item order) once all ended, so
    one failing package never leaves another half-run."""
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = [pool.submit(function, i, item) for i, item in enumerate(items)]
        errors = [f.exception() for f in futures]
    for error in errors:
        if error is not None:
            raise error


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def keyless_violations(artifact):
    """Functions that would need a verification key or transpilation in TXE."""
    return [
        function["name"]
        for function in artifact["functions"]
        if not function.get("is_unconstrained")
        or "abi_utility" not in function.get("custom_attributes", [])
    ]


def stripped_sha256(artifact):
    """Digest of an Aztec contract artifact without file_map, debug_symbols and
    Noir's source-dependent function hash, as the bytecode-parity checks
    compare."""
    top = {k: v for k, v in artifact.items() if k != "file_map"}
    top["functions"] = sorted(
        (
            {k: v for k, v in f.items() if k not in {"debug_symbols", "hash"}}
            for f in artifact["functions"]
        ),
        key=lambda f: f["name"],
    )
    return hashlib.sha256(
        json.dumps(top, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def child_env():
    """The environment for nargo and the TXE: the operator's, unchanged. The
    runner sets no CPU, thread, affinity or RAM cap; it records peak RSS
    instead (scripts/txe.sh runs everything under nice)."""
    return dict(os.environ)


def pinned_tools(profile):
    """The profile's tool paths from the environment, after checking that each
    reports its pinned version. scripts/toolchain.sh sets both."""
    tools = {}
    for name, version_name in PROFILES[profile].items():
        path, want = os.environ.get(name), os.environ.get(version_name)
        if not path or not want:
            raise SystemExit(
                f"{name} and {version_name} are unset; run scripts/txe.sh "
                "(it sources scripts/toolchain.sh)"
            )
        try:
            got = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=60
            ).stdout.splitlines()
        except OSError as error:
            raise SystemExit(f"{name}={path} cannot run: {error}") from error
        first = got[0].strip() if got else ""
        # Exact match: nargo prints "nargo version = <v>", bb prints "<v>".
        if first not in (want, f"nargo version = {want}"):
            raise SystemExit(
                f"{name}={path} reports {first!r}, the {profile} profile needs {want}"
            )
        tools[name] = Path(path)
    return tools


def prune_runs(keep):
    """Delete the oldest run directories so that `keep - 1` remain before the
    new run starts."""
    if keep < 1:
        raise SystemExit("TXE_KEEP_RUNS must be at least 1")
    if not RUNS.is_dir():
        return
    runs = sorted(
        (d for d in RUNS.iterdir() if d.is_dir() and d.name.isdigit()),
        key=lambda d: int(d.name),
    )
    for old in runs[: max(0, len(runs) - (keep - 1))]:
        shutil.rmtree(old)


def server_env(env, port):
    """Add loopback TXE settings without replacing operator Node/resource options."""
    return dict(env, TXE_PORT=str(port), LOG_LEVEL="warn")


def wait_server_ready(server, ready_fd, token, timeout=30):
    """Read a private acknowledgement written by this child after listen(0).

    The kernel allocates the port while Node owns its listening socket. No
    TCP probe can mistake an unrelated listener for the spawned TXE instance.
    """
    deadline = time.monotonic() + timeout
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(ready_fd, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if server.poll() is not None:
                raise RuntimeError("TXE exited before startup acknowledgement")
            if not selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                continue
            block = os.read(ready_fd, 4096)
            if not block:
                raise RuntimeError("TXE closed startup channel before readiness")
            data.extend(block)
            if len(data) > 4096:
                raise RuntimeError("Invalid TXE startup acknowledgement")
            if b"\n" not in data:
                continue
            try:
                record = json.loads(data)
            except (ValueError, UnicodeError) as error:
                raise RuntimeError("Invalid TXE startup acknowledgement") from error
            port = record.get("port") if isinstance(record, dict) else None
            if (
                not isinstance(record, dict)
                or record.get("token") != token
                or record.get("pid") != server.pid
                or type(port) is not int
                or not 0 < port < 65536
                or server.poll() is not None
            ):
                raise RuntimeError("TXE startup ownership acknowledgement differs")
            return port
    raise TimeoutError("TXE startup timed out")


def stop_server(server):
    """Stop only the spawned server's session, including surviving descendants."""
    try:
        os.killpg(server.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    finally:
        # A parent may exit promptly while its children remain in this group.
        try:
            os.killpg(server.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        server.wait()


def children_peak_rss_kib():
    """Largest RSS of any child reaped so far (Linux ru_maxrss is in KiB)."""
    return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss


def included_tests(
    listing, excluded_modules, package, included_modules=(), excluded_tests=()
):
    """Test names from `nargo test --list-tests` output (one `<package> <test>`
    line per test), and those that run: outside the excluded modules and, when
    `included_modules` is not empty, inside one of them. A module is a name
    path (`contract_test`, `test::constrained`) and holds every test below it.
    `excluded_tests` are full test names that never run.
    Any other line, or no test at all, is an error, so a changed listing format
    can never skip tests silently."""
    names = []
    for line in listing.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 2 or fields[0] != package:
            raise ValueError(f"Unexpected nargo --list-tests line: {line!r}")
        names.append(fields[1])
    if not names:
        raise ValueError(f"nargo --list-tests found no test in {package}")

    def inside(name, modules):
        return any(name.startswith(module + "::") for module in modules)

    kept = [
        n
        for n in names
        if not inside(n, excluded_modules)
        and n not in excluded_tests
        and (not included_modules or inside(n, included_modules))
    ]
    return names, kept


def may_select(package_dir, excluded_modules, excluded_tests):
    """Whether a package's sources may hold a test the run leaves out.

    A source scan decides, so a package without such a module or test needs no
    `nargo test --list-tests` (8-10 s per package). The scan is conservative: a
    module counts as present when a `mod <name>` declaration or a file or
    directory `<name>` exists for the last component of its path, and a test
    when `fn <name>` occurs; a false positive only costs the listing."""
    wanted = {m.split("::")[-1] for m in excluded_modules}
    tests = {t.split("::")[-1] for t in excluded_tests}
    if not wanted and not tests:
        return False
    for path in sorted(Path(package_dir, "src").rglob("*.nr")):
        if path.stem in wanted or path.parent.name in wanted:
            return True
        text = path.read_text(errors="replace")
        for name in wanted:
            if re.search(rf"\bmod\s+{re.escape(name)}\b", text):
                return True
        for name in tests:
            if re.search(rf"\bfn\s+{re.escape(name)}\b", text):
                return True
    return False


def lexical(path):
    """`path` normalized without following symlinks, as Nargo resolves
    dependency paths."""
    return Path(os.path.normpath(path))


def stage(root, staged, packages):
    """Copy the listed packages and their unlisted local path dependencies
    (Nargo.toml and src/ only) into `staged`. Dependencies under deps/ are
    used in place through the workspace's deps link and are not copied.
    Returns the listed source hashes, the digest of every local package, and
    the remote dependencies. A staged folder can be an ancestor of another
    staged package, so folders may already exist."""
    root = Path(root)
    # A contract may be both a test package and a deployment prerequisite.
    packages = list(dict.fromkeys(packages))
    source_hashes = {}
    for relative in packages:
        source = lexical(root / relative)
        if (
            not source.is_relative_to(root)
            or source.is_relative_to(root / DEPS)
            or not source.resolve().is_relative_to(root)
        ):
            raise ValueError(
                f"Test package {relative} must be source in this repository "
                "(not under deps/ and not a link out of the repository)"
            )
        target = staged / relative
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / "Nargo.toml", target)
        shutil.copytree(source / "src", target / "src")
        for path in [source / "Nargo.toml", *sorted((source / "src").rglob("*.nr"))]:
            source_hashes[str(path.relative_to(root))] = sha(path)
    dependency_hashes, remotes = {}, []

    def closure(package):
        manifest = lexical(package) / "Nargo.toml"
        if not manifest.is_relative_to(root):
            raise ValueError(
                f"Path dependency {manifest.parent} is outside the repository; "
                "reach outside sources through deps/"
            )
        key = str(manifest.relative_to(root))
        if key in dependency_hashes:
            return
        files = [manifest, *sorted((manifest.parent / "src").rglob("*.nr"))]
        folder = manifest.parent.relative_to(root)
        in_deps = manifest.is_relative_to(root / DEPS)
        if not in_deps and not manifest.resolve().is_relative_to(root):
            raise ValueError(
                f"Path dependency {folder} links out of the repository; "
                "reach outside sources through deps/"
            )
        if not in_deps and not (staged / folder / "Nargo.toml").exists():
            # Stage a local path dependency that the config does not list, so
            # its packages resolve in the copied workspace. It is not tested.
            (staged / folder).mkdir(parents=True, exist_ok=True)
            shutil.copy2(manifest, staged / folder)
            shutil.copytree(manifest.parent / "src", staged / folder / "src")
        content = {str(p.relative_to(manifest.parent)): sha(p) for p in files}
        dependency_hashes[key] = hashlib.sha256(
            json.dumps(content, sort_keys=True).encode()
        ).hexdigest()
        for dep in tomllib.loads(manifest.read_text()).get("dependencies", {}).values():
            if "path" in dep:
                closure(manifest.parent / dep["path"])
            else:
                remotes.append(dep)

    for relative in packages:
        closure(root / relative)
    return source_hashes, dependency_hashes, remotes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--contracts", action="store_true")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="hosted-v6")
    args = parser.parse_args()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text())
    if config.get("txe_profile", "hosted-v6") != args.profile:
        raise ValueError("TXE config/profile mismatch; select its explicit --profile")
    # Seconds allowed for each package's `nargo test` (all its tests together),
    # from the config's "test_timeout_seconds", default 360. The AMM suite sets
    # 600. A run that exceeds it is killed and fails; raise it for packages with
    # large constrained tests or slow hosts, rather than splitting packages.
    test_timeout = config.get("test_timeout_seconds", 360)
    if (
        not isinstance(test_timeout, int)
        or isinstance(test_timeout, bool)
        or test_timeout < 1
    ):
        raise SystemExit("test_timeout_seconds must be a positive integer")
    started = time.monotonic()
    tools = pinned_tools(args.profile)
    nargo, bb = tools["CONTRACT_NARGO_BIN"], tools["BB_BIN"]
    for world in ("aztec-world", "foundation-world"):
        if not (ROOT / DEPS / world).is_dir():
            raise SystemExit(f"{DEPS}/{world} is missing; run scripts/bootstrap.sh")
    txe_dir = TXE_DIR
    # serve.mjs starts the pinned package's server so that a test session
    # survives a long unconstrained computation between oracle calls.
    txe = txe_dir / "serve.mjs"
    # The installed TXE must be the version package.json and the lockfile pin.
    expected = json.loads((txe_dir / "package.json").read_text())["devDependencies"][
        "@aztec-labs/txe"
    ]
    locked = json.loads((txe_dir / "package-lock.json").read_text())["packages"][
        "node_modules/@aztec-labs/txe"
    ]["version"]
    try:
        installed = json.loads(
            (txe_dir / "node_modules/@aztec-labs/txe/package.json").read_text()
        )["version"]
    except FileNotFoundError:
        installed = None
    if not installed == locked == expected:
        raise SystemExit(
            f"@aztec-labs/txe is {installed} in scripts/txe/node_modules, {locked} "
            f"in the lockfile and {expected} in package.json; run "
            "npm ci --prefix scripts/txe --no-audit --no-fund"
        )
    if config.get("deployed_contracts") and not args.contracts:
        raise SystemExit(
            "deployed_contracts need --contracts: compiling them and running "
            "bb aztec_process generates verification keys (it reads the SRS)"
        )
    prune_runs(KEEP_RUNS)
    run = RUNS / str(time.time_ns())
    staged = run / "workspace"
    staged.mkdir(parents=True)
    # The copied Nargo.toml files reach the Aztec worlds through deps/ by
    # relative path; this link puts deps/ at the same place in the workspace.
    (staged / DEPS).symlink_to(ROOT / DEPS, target_is_directory=True)
    keyless = config.get("keyless_contracts", [])
    contracts = [
        {"path": c} if isinstance(c, str) else dict(c)
        for c in config.get("contracts", [])
    ]
    deployed = [
        {"path": c} if isinstance(c, str) else dict(c)
        for c in config.get("deployed_contracts", [])
    ]
    packages = (
        config["packages"]
        + [c["path"] for c in deployed]
        + [c["path"] for c in contracts]
        + keyless
    )
    source_hashes, dependency_hashes, remotes = stage(ROOT, staged, packages)
    report = {
        "passed": False,
        "txe_profile": args.profile,
        "proofs_generated": 0,
        "contracts_enabled": args.contracts,
        "test_timeout_seconds": test_timeout,
        "keyless_contracts": {},
        "deployed_contracts": [c["path"] for c in deployed],
        "contracts": {},
        "compiler_sha256": sha(nargo),
        "backend_sha256": sha(bb),
        "compiler_version": subprocess.check_output(
            [nargo, "--version"], text=True
        ).strip(),
        "txe_version": expected,
        "txe_lock_sha256": sha(txe_dir / "package-lock.json"),
        "txe_launcher_sha256": {name: sha(txe_dir / name) for name in TXE_LAUNCHER},
        "source_sha256": source_hashes,
        "local_package_digests": dependency_hashes,
        "remote_dependencies": remotes,
        "commands": [],
        "scope": "TXE tests of the listed packages; keyless contract deployment; with --contracts, compiled contract deployment and execution. No proofs or network transactions.",
    }
    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    scratch = tempfile.mkdtemp(prefix="noir_txe.", dir=TMP_ROOT)
    env = dict(child_env(), TMPDIR=scratch)

    lock = threading.Lock()

    def command(argv, label, timeout=360):
        log = run / f"{label}.log"
        start = time.monotonic()
        with log.open("w") as stream:
            proc = subprocess.Popen(
                list(map(str, argv)),
                cwd=staged,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                # wait4 returns this child's own resource usage (peak RSS).
                while True:
                    pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
                    if pid:
                        proc.returncode = os.waitstatus_to_exitcode(status)
                        code = proc.returncode
                        break
                    if time.monotonic() - start > timeout:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    time.sleep(0.25)
            except BaseException:
                if proc.returncode is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    os.waitpid(proc.pid, 0)
                raise
        text = log.read_text()
        tests = test_events(text)
        if tests:
            passed = [sum(1 for t in tests if t["event"] == "ok")]
        else:
            passed = re.findall(
                r"(\d+) tests? passed", re.sub(r"\x1b\[[0-9;]*m", "", text)
            )
        row = {
            "command": list(map(str, argv)),
            "log": log.name,
            "exit_code": code,
            "seconds": round(time.monotonic() - start, 3),
            "peak_rss_kib": usage.ru_maxrss,
            "tests_passed": int(passed[-1]) if passed else None,
            "children_peak_rss_kib_so_far": children_peak_rss_kib(),
        }
        if tests:
            # Each test's own seconds, slowest first ("exec_time" of nargo's
            # JSON report; a thread's first test includes elaborating the
            # package for that thread).
            row["tests"] = sorted(tests, key=lambda t: -t["seconds"])
        with lock:
            report["commands"].append(row)
        print(
            f"{label}: exit {code}" + (f", {passed[-1]} passed" if passed else ""),
            flush=True,
        )
        for t in tests:
            if t["event"] == "failed":
                print(f"  FAILED {t['name']}\n{t.get('output', '')}", flush=True)
        if code:
            raise RuntimeError(f"{label} failed: {log}")

    def build_contract(contract, tag):
        """Compile (or reuse the artifact of) a contract package in the copied
        workspace and run `bb aztec_process` on its artifacts. Returns the
        staged package folder and the compiler flags."""
        package = staged / contract["path"]
        # Contract compiler flags, default "--inliner-aggressiveness 0" (the
        # flag every TXE test run here also uses). The inliner setting changes
        # the bytecode and so the contract class id; a contract that must match
        # a class id built elsewhere sets that build's flags in its config
        # object ("compiler_flags").
        flags = contract.get("compiler_flags", ["--inliner-aggressiveness", "0"])
        if contract.get("artifact"):
            reused = Path(contract["artifact"])
            name = contract["artifact_name"]
            if "/" in name or not name.endswith(".json"):
                raise ValueError("artifact_name must be a file name")
            (package / "target").mkdir(exist_ok=True)
            shutil.copyfile(reused, package / "target" / name)
            with lock:
                report["commands"].append(
                    {
                        "command": ["reuse", str(reused)],
                        "artifact_sha256": sha(reused),
                        "exit_code": 0,
                    }
                )
        else:
            # Compile timeout: "timeout_seconds" of the entry, default 360 s.
            command(
                [nargo, "compile", "--program-dir", package, *flags],
                f"compile-{tag}",
                contract.get("timeout_seconds", 360),
            )
        artifacts = list((package / "target").glob("*.json"))
        if not artifacts:
            raise RuntimeError("No compiled contract artifacts")
        for j, artifact in enumerate(artifacts):
            with lock:
                row = report["contracts"].setdefault(
                    str(artifact.relative_to(staged)), {}
                )
            row["stripped_sha256"] = stripped_sha256(json.loads(artifact.read_text()))
            # Key generation. `bb aztec_process` transpiles public bytecode and
            # generates each private function's verification key, which reads
            # the SRS (CRS download or ~/.bb-crs) and takes most of a
            # --contracts run. It runs only here, for contracts a --contracts
            # run builds; a run without --contracts refuses configs that need
            # it. Default timeout 360 s per artifact ("keygen_timeout_seconds").
            command(
                [bb, "aztec_process", "-i", artifact],
                f"keygen-{tag}-{j}",
                contract.get("keygen_timeout_seconds", 360),
            )
            row["processed_sha256"] = sha(artifact)
        return package, flags

    # Node binds port 0 itself and acknowledges the listening socket over a
    # private inherited pipe. There is no reserve/close/rebind window.
    server = None
    try:
        with (run / "txe.log").open("w") as stream:
            ready_read, ready_write = os.pipe()
            token = secrets.token_hex(32)
            try:
                try:
                    server = subprocess.Popen(
                        [os.environ.get("NODE_BIN", "node"), str(txe)],
                        cwd=staged,
                        env=dict(
                            server_env(env, 0),
                            TXE_READY_FD=str(ready_write),
                            TXE_READY_TOKEN=token,
                        ),
                        pass_fds=(ready_write,),
                        stdout=stream,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )
                finally:
                    os.close(ready_write)
                # The TXE server gets 30 s (wait_server_ready's default) to
                # load and acknowledge its port; it takes a few seconds on the
                # reference host. Raise it only for a much slower host.
                port = wait_server_ready(server, ready_read, token)
                report["txe_port"] = port
                report["txe_pid"] = server.pid
            finally:
                os.close(ready_read)
            for i, relative in enumerate(keyless):
                package = staged / relative
                command(
                    [
                        nargo,
                        "compile",
                        "--program-dir",
                        package,
                        "--inliner-aggressiveness",
                        "0",
                    ],
                    f"compile-keyless-{i}",
                )
                artifacts = sorted((package / "target").glob("*.json"))
                if not artifacts:
                    raise RuntimeError("No compiled contract artifacts")
                for j, artifact in enumerate(artifacts):
                    violations = keyless_violations(json.loads(artifact.read_text()))
                    if violations:
                        raise RuntimeError(
                            f"{artifact.name} needs verification keys: {violations}"
                        )
                    command(
                        [bb, "aztec_process", "-i", artifact],
                        f"process-keyless-{i}-{j}",
                    )
                    processed = json.loads(artifact.read_text())
                    if not processed.get("transpiled") or any(
                        "verification_key" in function
                        for function in processed["functions"]
                    ):
                        raise RuntimeError(f"{artifact.name} was not processed keyless")
                    report["keyless_contracts"][str(artifact.relative_to(staged))] = (
                        sha(artifact)
                    )
            excluded = config.get("exclude_test_modules", [])
            included = config.get("include_test_modules", [])
            excluded_names = config.get("exclude_tests", [])
            report["exclude_tests"] = excluded_names
            report["exclude_test_modules"] = excluded
            report["include_test_modules"] = included
            # "test_threads": tests at a time in each package's `nargo test`,
            # each test its own TXE session (see the module docstring); null
            # leaves nargo's default. "package_jobs": packages tested side by
            # side against the one server, default all of them.
            threads = env_int("TXE_TEST_THREADS") or positive_or_none(
                config.get("test_threads", DEFAULT_TEST_THREADS), "test_threads"
            )
            jobs = env_int("TXE_PACKAGE_JOBS") or positive_or_none(
                config.get("package_jobs"), "package_jobs"
            )
            jobs = jobs or len(config["packages"]) or 1
            report["test_threads"] = threads
            report["package_jobs"] = jobs
            # The test packages deploy these contracts, so their processed
            # artifacts must exist before the first `nargo test`. They build
            # side by side (each build is one nargo or bb process).
            run_all(
                len(deployed),
                lambda i, contract: build_contract(contract, f"deployed-{i}"),
                deployed,
            )

            def test_package(i, relative):
                selection = []
                if included or may_select(staged / relative, excluded, excluded_names):
                    # Run every test except those of the excluded modules (for
                    # example contract_test, which needs the contract artifacts
                    # of a --contracts run), or only those of the included ones.
                    listing = subprocess.run(
                        [
                            nargo,
                            "test",
                            "--list-tests",
                            "--program-dir",
                            staged / relative,
                        ],
                        cwd=staged,
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=test_timeout,
                    )
                    (run / f"list-{i}.log").write_text(listing.stdout + listing.stderr)
                    if listing.returncode:
                        raise RuntimeError(
                            f"Listing tests failed: {run / f'list-{i}.log'}"
                        )
                    listing_stdout = listing.stdout
                    package_name = tomllib.loads(
                        (staged / relative / "Nargo.toml").read_text()
                    )["package"]["name"]
                    names, selection = included_tests(
                        listing_stdout,
                        excluded,
                        package_name,
                        included,
                        excluded_names,
                    )
                    report.setdefault("excluded_tests", {})[relative] = sorted(
                        set(names) - set(selection)
                    )
                    if not selection:
                        if included:
                            raise RuntimeError(
                                f"include_test_modules {included} select no test of {relative}"
                            )
                        return
                    selection = ["--exact", *selection]
                else:
                    # No excluded module or test in the sources: run it all.
                    report.setdefault("excluded_tests", {})[relative] = []
                command(
                    [
                        nargo,
                        "test",
                        *selection,
                        "--program-dir",
                        staged / relative,
                        "--oracle-resolver",
                        f"http://127.0.0.1:{port}",
                        *(
                            ["--test-threads", str(threads)]
                            if threads is not None
                            else []
                        ),
                        "--inliner-aggressiveness",
                        "0",
                        # one JSON line per test with its time (report.json "tests")
                        "--format",
                        "json",
                    ],
                    f"tests-{i}",
                    test_timeout,
                )

            run_all(jobs, test_package, config["packages"])
            if args.contracts:
                for i, contract in enumerate(contracts):
                    package, flags = build_contract(contract, str(i))
                    filters = (
                        [contract["test_filter"]] if contract.get("test_filter") else []
                    )
                    command(
                        [
                            nargo,
                            "test",
                            *filters,
                            "--program-dir",
                            package,
                            "--oracle-resolver",
                            f"http://127.0.0.1:{port}",
                            "--test-threads",
                            "1",
                            *flags,
                        ],
                        f"contracts-{i}",
                        contract.get("test_timeout_seconds", 600),
                    )
        report["passed"] = True
    finally:
        if server is not None:
            stop_server(server)
        shutil.rmtree(scratch, ignore_errors=True)
        report["seconds"] = round(time.monotonic() - started, 3)
        report["peak_rss_kib"] = children_peak_rss_kib()
        report["tests_passed"] = sum(
            c.get("tests_passed") or 0 for c in report["commands"]
        )
        (run / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Run directory: {run}", flush=True)


if __name__ == "__main__":
    main()
