import hashlib
from contextlib import contextmanager
import fcntl
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ARCHIVE_LIMIT = 16 * 1024 * 1024
EXTRACTED_LIMIT = 32 * 1024 * 1024
MEMBER_LIMIT = 512
SOURCE_DIRECTORIES = ("src", "test", "script", "bytecode")
SOURCE_FILES = ("foundry.toml", "foundry.lock", "VERSION")


def checkout_cache_id(repository):
    return hashlib.sha256(str(repository.resolve()).encode()).hexdigest()[:16]


@contextmanager
def build_lock(repository, cache):
    directory = cache / "contracts"
    if directory.is_symlink():
        raise ValueError("Build cache must not contain a symlink")
    directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(directory / f"{checkout_cache_id(repository)}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(descriptor).st_nlink != 1:
            raise ValueError("Build lock must not have hard links")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another contract build is running for this checkout") from None
        yield
    finally:
        os.close(descriptor)


def dependency_spec(repository):
    try:
        lock = json.loads((repository / "crates/agentkeys-chain/foundry.lock").read_text())
        dependency = lock["lib/forge-std"]
        revision = dependency["tag"]["rev"]
        checksum = dependency["archive_sha256"]
    except (KeyError, TypeError, json.JSONDecodeError):
        raise ValueError("Invalid pinned contract dependency lock") from None
    if not isinstance(revision, str) or len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise ValueError("Invalid pinned contract dependency revision")
    if not isinstance(checksum, str) or len(checksum) != 64 or any(character not in "0123456789abcdef" for character in checksum):
        raise ValueError("Invalid pinned contract dependency checksum")
    return revision, checksum


def cache_directory():
    configured = os.environ.get("AGENT_TERRIER_CACHE_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "agent-terrier"


def verified_archive(repository, cache, offline):
    revision, checksum = dependency_spec(repository)
    download_directory = cache / "downloads"
    if download_directory.is_symlink():
        raise ValueError("Dependency cache must not contain a symlink")
    download_directory.mkdir(parents=True, exist_ok=True)
    archive_path = download_directory / f"forge-std-{revision}.tar.gz"
    if archive_path.is_symlink():
        raise ValueError("Dependency archive must not be a symlink")
    if not archive_path.exists():
        if offline:
            raise RuntimeError("Contract dependency is not downloaded; run terrier contracts setup first")
        request = urllib.request.Request(
            f"https://api.github.com/repos/foundry-rs/forge-std/tarball/{revision}",
            headers={"User-Agent": "agent-terrier-local"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            archive = response.read(ARCHIVE_LIMIT + 1)
        verify_checksum(archive, checksum)
        with tempfile.NamedTemporaryFile(dir=download_directory, delete=False) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(archive)
        try:
            temporary_path.replace(archive_path)
        finally:
            temporary_path.unlink(missing_ok=True)
    archive = archive_path.read_bytes()
    verify_checksum(archive, checksum)
    return archive


def verify_checksum(archive, checksum):
    if len(archive) > ARCHIVE_LIMIT or hashlib.sha256(archive).hexdigest() != checksum:
        raise ValueError("Contract dependency checksum mismatch; cached content was not used")


def archive_files(archive):
    files = {}
    total_size = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        archive_root = None
        for index, member in enumerate(package):
            path = PurePosixPath(member.name)
            if index >= MEMBER_LIMIT or not path.parts or member.size < 0:
                raise ValueError("Invalid contract dependency archive size")
            if archive_root is None:
                archive_root = path.parts[0]
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != archive_root:
                raise ValueError("Unsafe contract dependency archive path")
            if member.isdir():
                continue
            if not member.isfile() or len(path.parts) < 2:
                raise ValueError("Contract dependency archive contains a link or special file")
            relative = Path(*path.parts[1:])
            total_size += member.size
            if total_size > EXTRACTED_LIMIT or relative in files:
                raise ValueError("Invalid contract dependency archive contents")
            files[relative] = package.extractfile(member).read()
    if Path("src/Test.sol") not in files or Path("src/Script.sol") not in files:
        raise ValueError("Contract dependency is missing its public entry points")
    return files


def write_if_changed(path, contents):
    if path.is_symlink():
        raise ValueError("Build cache contains a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_bytes() != contents:
        path.write_bytes(contents)


def prepare_project(repository, cache, dependency_files):
    checkout_id = checkout_cache_id(repository)
    project = cache / "contracts" / checkout_id
    if (cache / "contracts").is_symlink() or project.is_symlink():
        raise ValueError("Build cache must not contain a symlink")
    marker = project / ".agent-terrier-build"
    if project.exists():
        if marker.is_symlink() or not marker.is_file() or marker.read_text() != checkout_id:
            raise ValueError("Refusing an unowned contract build directory")
    else:
        project.mkdir(parents=True)
        marker.write_text(checkout_id)
    for path in project.rglob("*"):
        if path.is_symlink():
            raise ValueError("Build cache contains a symlink")
    contract_source = repository / "crates/agentkeys-chain"
    expected = {}
    for directory in SOURCE_DIRECTORIES:
        if (contract_source / directory).is_symlink():
            raise ValueError("Contract source contains a symlink")
        for path in (contract_source / directory).rglob("*"):
            if path.is_symlink():
                raise ValueError("Contract source contains a symlink")
            suffix = ".hex" if directory == "bytecode" else ".sol"
            if path.is_file() and path.suffix == suffix:
                expected[path.relative_to(contract_source)] = path.read_bytes()
    for name in SOURCE_FILES:
        if (contract_source / name).is_symlink():
            raise ValueError("Contract source contains a symlink")
        expected[Path(name)] = (contract_source / name).read_bytes()
    expected.update({Path("lib/forge-std") / path: contents for path, contents in dependency_files.items()})
    for directory in (*SOURCE_DIRECTORIES, "lib"):
        for path in (project / directory).rglob("*"):
            if path.is_file() and path.relative_to(project) not in expected:
                path.unlink()
    for path, contents in expected.items():
        write_if_changed(project / path, contents)
    return project


def run(repository, action, offline=False, match_test=None):
    cache = cache_directory()
    archive = verified_archive(repository, cache, offline)
    with build_lock(repository, cache):
        project = prepare_project(repository, cache, archive_files(archive))
        return run_forge(project, action, offline, match_test)


def run_forge(project, action, offline, match_test):
    if action == "setup":
        print("Pinned contract dependency verified and local build cache prepared.")
        return 0
    forge = os.environ.get("AGENT_TERRIER_FORGE") or shutil.which("forge")
    if not forge:
        candidate = Path.home() / ".foundry/bin/forge"
        forge = str(candidate) if candidate.is_file() else None
    if not forge:
        raise RuntimeError("Foundry forge is required; install it before building contracts")
    command = [forge, action, "--root", ".", "--remappings", "forge-std/=lib/forge-std/src/"]
    if offline:
        command.append("--offline")
    if match_test:
        if action != "test":
            raise ValueError("--match-test is only valid for contract tests")
        command.extend(["--match-test", match_test])
    environment = {key: value for key, value in os.environ.items() if key in {
        "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR",
    }}
    return subprocess.run(command, cwd=project, env=environment, check=False).returncode
