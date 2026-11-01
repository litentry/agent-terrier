#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description="Build the shared browser client for both public apps.")
    parser.add_argument("--release", action="store_true", help="Use optimized release compilation")
    arguments = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[1]
    if not shutil.which("wasm-pack"):
        parser.error("Install wasm-pack before building the browser client")
    environment = os.environ.copy()
    encoded_flags = environment.get("CARGO_ENCODED_RUSTFLAGS")
    rust_flags = encoded_flags.split("\x1f") if encoded_flags else shlex.split(environment.get("RUSTFLAGS", ""))
    rust_flags.extend([
        f"--remap-path-prefix={repository_root}=/src",
        f"--remap-path-prefix={Path.home()}=/developer",
    ])
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(rust_flags)
    subprocess.run([
        "wasm-pack", "build", "crates/agentkeys-web-core", "--target", "web",
        "--release" if arguments.release else "--dev",
        "--out-dir", "../../target/browser-core", "--", "--features", "wasm", "--locked",
    ], cwd=repository_root, env=environment, check=True)
    output_directory = repository_root / "target/browser-core"
    for application, module_path in [
        ("parent-control", "lib/wasm/agentkeys-web-core"),
        ("device-display", "src/wasm/agentkeys-web-core"),
    ]:
        application_directory = repository_root / "apps" / application
        module_directory = application_directory / module_path
        public_directory = application_directory / "public/wasm"
        module_directory.mkdir(parents=True, exist_ok=True)
        public_directory.mkdir(parents=True, exist_ok=True)
        for filename in ["agentkeys_web_core.js", "agentkeys_web_core.d.ts", "agentkeys_web_core_bg.wasm"]:
            shutil.copy2(output_directory / filename, module_directory / filename)
        shutil.copy2(output_directory / "agentkeys_web_core_bg.wasm", public_directory)


if __name__ == "__main__":
    main()
