import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

from . import chain, contracts, deployment, local_state

DEFAULT_TRANSACTION_GAS = 8_000_000


def executable(repository):
    selected = Path(os.environ.get("AGENT_TERRIER_CLI", repository / "target/debug/agentkeys"))
    if not selected.is_file():
        raise ValueError("Build the public CLI with cargo build -p agentkeys-cli or set AGENT_TERRIER_CLI")
    return selected.resolve()


def run_cli(repository, profile_path, arguments, payload=None):
    environment = contracts.tool_environment()
    environment.update(AGENT_TERRIER_LOCAL_DEV="1", AGENTKEYS_CHAIN_PROFILE_FILE=str(profile_path))
    result = subprocess.run([str(executable(repository)), "chain", *arguments],
                            input=payload, capture_output=True, text=True, env=environment, timeout=90,
                            umask=0o077)
    if result.returncode:
        raise RuntimeError("Local owner command failed: " + result.stderr.strip())
    return json.loads(result.stdout)


def validate_name(name):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name):
        raise ValueError("Name must be lowercase letters, digits or hyphens, starting with a letter")


def device_identity(repository, state, name, operator, label, kind):
    validate_name(name)
    validate_name(label)
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", operator) or kind not in ("device", "delegate"):
        raise ValueError("Invalid operator identity or actor kind")
    directory = state / "devices" / name
    local_state.private_directory(state / "devices")
    local_state.private_directory(directory)
    enrollment_path = directory / "enrollment.json"
    identity_path = directory / "identity.json"
    identity = {"operator_omni":operator.lower(), "label":label, "kind":kind, "development_only":True}
    if identity_path.exists() or identity_path.is_symlink():
        if local_state.read_json(identity_path) != identity:
            raise ValueError("Existing actor identity differs; refusing key reuse")
        if not (directory / "device.key").exists():
            raise ValueError("Existing actor key is missing; restore the original key")
    enrollment = run_cli(repository, state / "chain-profile.json", ["device-identity",
        "--key-file", str(directory / "device.key"), "--operator-omni", operator,
        "--label", label, "--kind", kind])
    local_state.write_json(identity_path, identity)
    local_state.write_json(enrollment_path, enrollment)
    return {"development_only":True, "enrollment_file":str(enrollment_path), "enrollment":enrollment}


def execute(repository, state, action, name, actor=None, services=None, read_only=False, enrollment_file=None):
    validate_name(name)
    services = services or []
    if action not in ("register", "grant", "revoke", "bind", "unbind"):
        raise ValueError("Unsupported owner operation")
    if action == "register" and (actor or services or read_only):
        raise ValueError("Owner registration does not accept scope arguments")
    if action in ("grant", "revoke") and not actor:
        raise ValueError("Scope operations require --actor-omni")
    if (action in ("bind", "unbind")) != bool(enrollment_file):
        raise ValueError("Only bind/unbind require --enrollment-file")
    if action in ("bind", "unbind") and actor:
        raise ValueError("Binding uses the actor in the enrollment file")
    if action == "bind" and not services:
        raise ValueError("Bind requires at least one --service")
    if action == "unbind" and (services or read_only):
        raise ValueError("Unbind does not accept grant arguments")
    if action == "grant" and not services:
        raise ValueError("Grant requires at least one --service")
    if action == "revoke" and (services or read_only):
        raise ValueError("Revoke does not accept grant arguments")
    running = chain.status(state)
    if not running["running"]:
        raise RuntimeError("Start the owned local chain before owner operations")
    profile_path = state / "chain-profile.json"
    profile = local_state.read_json(profile_path)
    if profile.get("rpc", {}).get("http") != running["rpc_http"]:
        raise ValueError("Local profile endpoint changed; run chain deploy to verify and refresh it")
    if profile.get("contract_set_version") != (repository / "crates/agentkeys-chain/VERSION").read_text().strip():
        raise ValueError("Local contract version differs from source")
    deployment.verify_contracts(running["rpc_http"], {item["name"]:item["address"] for item in profile["contracts"]})
    fingerprint = hashlib.sha256(json.dumps({"chain_id":profile["chain_id"], "contracts":profile["contracts"]}, sort_keys=True).encode()).hexdigest()
    directory = state / "owners" / name
    if action != "register" and not directory.exists():
        raise ValueError("Register this local owner first")
    local_state.private_directory(state / "owners")
    local_state.private_directory(directory)
    identity_path = directory / "identity.json"
    if identity_path.exists() or identity_path.is_symlink():
        identity = local_state.read_json(identity_path)
        if identity.get("profile_identity") != fingerprint or identity.get("development_only") is not True:
            raise ValueError("Owner belongs to another contract deployment; refusing key reuse")
    else:
        identity = {"operator_omni":"0x" + secrets.token_hex(32), "profile_identity":fingerprint, "development_only":True}
        local_state.write_json(identity_path, identity)
    beneficiary, keystore, password_file = deployment.developer_wallet(state)
    arguments = ["prepare-owner", action, "--operator-omni", identity["operator_omni"],
                 "--key-file", str(directory / "passkey.pem"), "--device-key-file", str(directory / "device.key"),
                 "--beneficiary", beneficiary]
    if actor:
        arguments.extend(["--actor-omni", actor])
    if enrollment_file:
        arguments.extend(["--enrollment-file", str(enrollment_file)])
    for service in services:
        arguments.extend(["--service", service])
    if read_only:
        arguments.append("--read-only")
    plan = run_cli(repository, profile_path, arguments)
    if action == "register" and plan["already_registered"]:
        return {"registered":False, "verified":True, "development_only":True, "operator_omni":identity["operator_omni"],
                "account":plan["account"], "device_key_hash":plan["device_key_hash"]}
    endpoint = running["rpc_http"]
    chain.node_identity(endpoint, profile["chain_id"], running["instance_id"])
    funding = int(profile["funding"]["account_deposit_wei"])
    balance = int(chain.rpc(endpoint, "eth_getBalance", [plan["account"], "latest"]), 16)
    if balance < funding:
        chain.rpc(endpoint, "anvil_setBalance", [plan["account"], hex(funding)])
    gas_limit = int(os.environ.get("AGENT_TERRIER_OWNER_TRANSACTION_GAS", DEFAULT_TRANSACTION_GAS))
    if gas_limit <= 0:
        raise ValueError("Owner transaction gas must be positive")
    command = [contracts.foundry_binary("cast"), "send", plan["build"]["entry_point"],
               "--data", plan["transaction_data"], "--rpc-url", endpoint, "--gas-limit", str(gas_limit),
               "--keystore", str(keystore), "--password-file", str(password_file), "--json"]
    result = subprocess.run(command, env=contracts.tool_environment(), stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=90, umask=0o077)
    if result.returncode:
        raise RuntimeError("Owner operation submission failed; retry the same command to inspect current chain state")
    receipt = json.loads(result.stdout)
    verified = run_cli(repository, profile_path, ["verify-owner", "--transaction", receipt["transactionHash"]], json.dumps(plan))
    verified.update(operator_omni=identity["operator_omni"], device_key_hash=plan["device_key_hash"], action=action)
    if action == "register":
        verified["registered"] = True
    return verified
