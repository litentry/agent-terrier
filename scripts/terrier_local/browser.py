import os
import re
import stat
import subprocess

from . import data, local_state, owner


def open_public_request(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    metadata = os.fstat(descriptor)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1 or metadata.st_mode & 0o022):
        os.close(descriptor)
        raise ValueError("Browser request must be a regular owned file without links or shared write access")
    return os.fdopen(descriptor, "rb")


def approve(repository, state, arguments):
    identity, running, environment = data.command_context(repository, state, arguments.name)
    website = running["services"].get("website", {}).get("url")
    if not website:
        raise ValueError("Start the selected local website before approving browser access")
    confirmed = arguments.confirm_device_key_hash
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", confirmed):
        raise ValueError("Confirm the complete device fingerprint shown by your browser")
    directory = state / "owners" / arguments.name
    operations = local_state.private_directory(directory / "browser-approvals")
    operations = local_state.private_directory(operations / confirmed.lower())
    command = [str(owner.executable(repository)), "local", "browser", *identity,
        "--key-file", str(directory / "passkey.pem"), "--operations-dir", str(operations),
        "--website-origin", website, "--confirm-device-key-hash", confirmed]
    with open_public_request(arguments.request_file) as request:
        return subprocess.run(command, stdin=request, env=environment, timeout=120, umask=0o077).returncode
