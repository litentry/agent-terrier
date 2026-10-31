from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile


def private_directory(directory):
    if directory.is_symlink():
        raise ValueError("Local state must not be a symlink")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = directory.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("Local state must be an owner-only directory (0700)")
    return directory


def state_directory(repository):
    configured = os.environ.get("AGENT_TERRIER_STATE_DIR")
    directory = Path(configured).expanduser() if configured else Path(
        os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))
    ) / "agent-terrier"
    if directory.is_symlink():
        raise ValueError("Local state must not be a symlink")
    directory = directory.resolve()
    if directory == repository.resolve() or repository.resolve() in directory.parents:
        raise ValueError("Local state must be outside the source repository")
    return private_directory(directory)


def open_private(path, flags=os.O_RDONLY):
    descriptor = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    metadata = os.fstat(descriptor)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1 or metadata.st_mode & 0o077):
        os.close(descriptor)
        raise ValueError("Local state files must be regular, owner-only files without links")
    return descriptor


def read_json(path):
    with os.fdopen(open_private(path)) as source:
        return json.load(source)


def write_private(path, contents):
    if path.exists() or path.is_symlink():
        os.close(open_private(path))
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path, value):
    write_private(path, (json.dumps(value, indent=2) + "\n").encode())


@contextmanager
def exclusive_lock(path):
    descriptor = open_private(path, os.O_CREAT | os.O_RDWR)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another local operation owns this state") from None
        yield
    finally:
        os.close(descriptor)
