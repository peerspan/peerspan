#!/usr/bin/env python3
"""Measure equivalent host-service build workloads in disposable source copies.

Dependencies must already be downloaded. Clean builds use isolated build caches;
normal developer caches and source files are never modified. These measurements
compare the current implementations and dependencies, not language performance
in general. The Go host builds with its default optimizations; Rust dev builds
are unoptimized. Release measurements are reported separately.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import time


def measure(command, directory, environment):
    started = time.perf_counter()
    result = subprocess.run(command, cwd=directory, env=environment, capture_output=True, text=True)
    elapsed = time.perf_counter() - started
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stdout}\n{result.stderr}")
    return round(elapsed, 3)


def benchmark(source, language, root, runs):
    destination = root / language
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".git", "target", ".peerspans", "__pycache__"))
    environment = dict(os.environ)
    if language == "go":
        environment["GOCACHE"] = str(root / "go-cache")
        environment["GOTOOLCHAIN"] = "local"
        environment["GOPROXY"] = "off"
        build = ["go", "build", "-o", str(root / "peerspan-host-go"), "./cmd/peerspan-host"]
        tests = ["go", "test", "./internal/host", "./cmd/peerspan-host"]
        release = ["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(root / "peerspan-host-go-release"), "./cmd/peerspan-host"]
        leaf = destination / "internal/host/model.go"
        comment = "// build timing edit\n"
    else:
        environment["CARGO_TARGET_DIR"] = str(root / "rust-target")
        build = ["cargo", "build", "--locked", "--offline"]
        tests = ["cargo", "test", "--locked", "--offline"]
        release = ["cargo", "build", "--locked", "--offline", "--release"]
        leaf = destination / "src/model.rs"
        comment = "// build timing edit\n"
    print(f"{language}: clean build", flush=True)
    clean = measure(build, destination, environment)
    warm = [measure(build, destination, environment) for _ in range(runs)]
    # Warm test dependencies so edit measurements do not include their first build.
    measure(tests, destination, environment)
    edited_build, edited_tests = [], []
    original = leaf.read_text()
    for index in range(runs):
        leaf.write_text(original + comment + f"// sample {index}\n")
        edited_build.append(measure(build, destination, environment))
        leaf.write_text(original + comment + f"// test sample {index}\n")
        edited_tests.append(measure(tests, destination, environment))
    print(f"{language}: release build", flush=True)
    release_seconds = measure(release, destination, environment)
    result = {
        "clean_build_seconds": clean,
        "warm_no_change_median_seconds": round(statistics.median(warm), 3),
        "edit_build_median_seconds": round(statistics.median(edited_build), 3),
        "edit_test_median_seconds": round(statistics.median(edited_tests), 3),
        "first_release_build_seconds": release_seconds,
        "samples": {"warm_no_change": warm, "edit_build": edited_build, "edit_test": edited_tests},
    }
    print(f"{language}: {json.dumps(result)}", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-repo", type=Path, required=True)
    parser.add_argument("--rust-repo", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    result = {
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "go_version": subprocess.check_output(["go", "version"], text=True).strip(),
        "rust_version": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "runs": args.runs,
        "workload": "private host registry and owner-local administration; no peer networking or agent execution",
        "edit": "comment-only source change to model module; no algorithmic change",
        "cache": "isolated build caches; dependencies predownloaded; each tool's default compiler parallelism",
        "profiles": "Go default optimized build; Rust unoptimized dev build; release builds separate",
    }
    with tempfile.TemporaryDirectory(prefix="peerspan-build-timings-") as temporary:
        root = Path(temporary)
        result["go"] = benchmark(args.go_repo.resolve(), "go", root, args.runs)
        result["rust"] = benchmark(args.rust_repo.resolve(), "rust", root, args.runs)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
