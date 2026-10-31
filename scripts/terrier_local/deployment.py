import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile

from . import chain, contracts, local_state

DEPLOYMENT_TIMEOUT = 180
DEPLOYMENT_BALANCE_WEI = 100 * 10 ** 18
DEFAULT_AGENT_SLOTS = 3
ADDRESS_PATTERN = re.compile(r"0x[0-9a-fA-F]{40}\Z")


def valid_address(value):
    return isinstance(value, str) and ADDRESS_PATTERN.fullmatch(value) and int(value, 16) != 0


def developer_wallet(state):
    directory = state / "deployer"
    if not directory.exists() and not directory.is_symlink():
        staging = Path(tempfile.mkdtemp(prefix=".deployer-", dir=state))
        try:
            passphrase = secrets.token_urlsafe(32)
            local_state.write_private(staging / "password", passphrase.encode())
            environment = contracts.tool_environment()
            environment["CAST_PASSWORD"] = passphrase
            result = subprocess.run([
                contracts.foundry_binary("cast"), "wallet", "new", str(staging), "keystore", "--json",
            ], stdin=subprocess.DEVNULL, capture_output=True, env=environment, timeout=30, umask=0o077)
            if result.returncode:
                raise RuntimeError("Could not generate the disposable development deployer")
            os.close(local_state.open_private(staging / "keystore"))
            staging.rename(directory)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    local_state.private_directory(directory)
    os.close(local_state.open_private(directory / "password"))
    keystore = local_state.read_json(directory / "keystore")
    if not keystore.get("crypto", keystore.get("Crypto")):
        raise ValueError("Invalid development deployer keystore")
    result = subprocess.run([
        contracts.foundry_binary("cast"), "wallet", "address", "--keystore", str(directory / "keystore"),
        "--password-file", str(directory / "password"),
    ], stdin=subprocess.DEVNULL, capture_output=True, text=True, env=contracts.tool_environment(), timeout=30)
    address = result.stdout.strip()
    if result.returncode or not valid_address(address):
        raise ValueError("Could not verify the development deployer keystore")
    return address, directory / "keystore", directory / "password"


def source_identity(repository):
    source = repository / "crates/agentkeys-chain"
    digest = hashlib.sha256()
    for directory in contracts.SOURCE_DIRECTORIES:
        for path in sorted((source / directory).rglob("*")):
            if path.is_file() and path.suffix in (".sol", ".hex"):
                digest.update(str(path.relative_to(source)).encode())
                digest.update(path.read_bytes())
    for name in contracts.SOURCE_FILES:
        digest.update(name.encode())
        digest.update((source / name).read_bytes())
    return digest.hexdigest()


def verify_contracts(endpoint, registry):
    if not isinstance(registry, dict) or not registry:
        raise ValueError("Deployment contract registry is empty or invalid")
    seen = set()
    for name, address in registry.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name) or not valid_address(address):
            raise ValueError("Invalid contract registry entry")
        if address.lower() in seen:
            raise ValueError("Duplicate deployed contract address")
        seen.add(address.lower())
        code = chain.rpc(endpoint, "eth_getCode", [address, "latest"])
        if not isinstance(code, str) or code in ("0x", "0x0", "0x00") or not code.startswith("0x"):
            raise RuntimeError(f"Deployed contract has no code: {name}")


def profile_identity(profile):
    return hashlib.sha256(json.dumps({"chain_id":profile["chain_id"], "contracts":profile["contracts"]}, sort_keys=True).encode()).hexdigest()


def active_profile(repository, state):
    running = chain.status(state)
    if not running["running"]:
        raise RuntimeError("Start the owned local chain before local operations")
    profile = local_state.read_json(state / "chain-profile.json")
    if profile.get("rpc", {}).get("http") != running["rpc_http"]:
        raise ValueError("Local profile endpoint changed; run chain deploy to verify and refresh it")
    if profile.get("contract_set_version") != (repository / "crates/agentkeys-chain/VERSION").read_text().strip():
        raise ValueError("Local contract version differs from source")
    verify_contracts(running["rpc_http"], {item["name"]:item["address"] for item in profile["contracts"]})
    return running, profile, profile_identity(profile)


def deploy(repository, state, offline=False, resume=False):
    current = chain.status(state)
    if not current["running"]:
        raise RuntimeError("Start the owned local chain before deploying contracts")
    endpoint = current["rpc_http"]
    profile_path = state / "chain-profile.json"
    version = (repository / "crates/agentkeys-chain/VERSION").read_text().strip()
    if profile_path.exists() or profile_path.is_symlink():
        profile = local_state.read_json(profile_path)
        if profile.get("contract_set_version") != version:
            raise ValueError("Contract version changed; explicit state migration or reset is required")
        verify_contracts(endpoint, {item["name"]: item["address"] for item in profile.get("contracts", [])})
        profile["rpc"] = {"http": endpoint, "wss": endpoint.replace("http:", "ws:", 1)}
        local_state.write_json(profile_path, profile)
        return {"deployed": False, "verified": True, "profile": str(profile_path), "version": version}

    deployment_directory = local_state.private_directory(state / "deployment")
    pending_path = deployment_directory / "pending.json"
    registry_path = deployment_directory / "contracts.json"
    source_hash = source_identity(repository)
    genesis_hash = chain.rpc(endpoint, "eth_getBlockByNumber", ["0x0", False])["hash"]
    pending = local_state.read_json(pending_path) if pending_path.exists() or pending_path.is_symlink() else None
    if pending and not resume:
        raise RuntimeError("An incomplete deployment exists; use chain deploy --resume after inspecting chain logs")
    if resume and not pending:
        raise ValueError("No incomplete deployment to resume")
    deployer, keystore, password_file = developer_wallet(state)
    if pending and (pending.get("version") != version or pending.get("source_hash") != source_hash
                    or pending.get("deployer") != deployer or pending.get("rpc_http") != endpoint
                    or pending.get("genesis_hash") != genesis_hash):
        raise ValueError("Incomplete deployment inputs changed; refusing an unsafe resume")
    cache = contracts.cache_directory()
    archive = contracts.verified_archive(repository, cache, offline)
    with contracts.build_lock(repository, cache):
        project = contracts.prepare_project(repository, cache, contracts.archive_files(archive))
        generated_registry = project / "deployment-registry.json"
        if not pending:
            if generated_registry.exists() or generated_registry.is_symlink():
                os.close(local_state.open_private(generated_registry))
                generated_registry.unlink()
            chain.rpc(endpoint, "anvil_setBalance", [deployer, hex(DEPLOYMENT_BALANCE_WEI)])
            local_state.write_json(pending_path, {
                "version": version, "source_hash": source_hash, "deployer": deployer,
                "rpc_http": endpoint, "genesis_hash": genesis_hash, "development_only": True,
            })
        command = [
            contracts.foundry_binary("forge"), "script", "script/DeployAgentKeysV1.s.sol:DeployAgentKeysV1",
            "--root", ".", "--remappings", "forge-std/=lib/forge-std/src/", "--rpc-url", endpoint,
            "--cache-path", str(deployment_directory / "cache"),
            "--sender", deployer, "--keystore", str(keystore), "--password-file", str(password_file),
            "--broadcast", "--slow", "--non-interactive",
        ]
        if offline:
            command.append("--offline")
        if resume:
            command.append("--resume")
        environment = contracts.tool_environment()
        environment.update({
            "SIGNER_GOVERNANCE": deployer, "SPONSOR_SIGNER": deployer,
            "AGENTKEYS_AGENT_SLOT_DEFAULT": str(DEFAULT_AGENT_SLOTS),
            "FOUNDRY_BROADCAST": str(deployment_directory / "broadcast"),
        })
        if registry_path.exists() or registry_path.is_symlink():
            os.close(local_state.open_private(registry_path))
        log = local_state.open_private(state / "deployment.log", os.O_CREAT | os.O_WRONLY | os.O_APPEND)
        try:
            result = subprocess.run(command, cwd=project, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=log, timeout=DEPLOYMENT_TIMEOUT, umask=0o077)
        finally:
            os.close(log)
            if not pending and generated_registry.exists():
                local_state.write_json(registry_path, local_state.read_json(generated_registry))
        if result.returncode:
            raise RuntimeError("Local deployment failed; inspect chain logs, then explicitly resume the same deployment")
    registry = local_state.read_json(registry_path)
    chain.node_identity(endpoint, current["chain_id"], current["instance_id"])
    verify_contracts(endpoint, registry)
    profile = chain.default_profile(repository)
    profile["rpc"] = {"http": endpoint, "wss": endpoint.replace("http:", "ws:", 1)}
    profile["contract_set_version"] = version
    profile["contracts"] = [{"name": name, "address": address} for name, address in sorted(registry.items())]
    local_state.write_json(profile_path, profile)
    pending_path.unlink()
    return {"deployed": True, "verified": True, "profile": str(profile_path), "version": version}
