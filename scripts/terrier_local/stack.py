import subprocess

from . import chain, deployment, services


OPERATION_ERRORS = (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired)


def status(state):
    components = {}
    for name, controller in (("chain", chain), ("services", services)):
        try:
            components[name] = controller.status(state)
        except OPERATION_ERRORS as error:
            components[name] = {"running": None, "error": str(error)}
    return {"development_only": True, "chain": components["chain"], "services": components["services"],
            "ready": components["chain"].get("running") is True and components["services"].get("ready") is True}


def stop(state):
    stopped_services = services.stop(state)
    if stopped_services.get("running") is not False:
        raise RuntimeError("Services did not confirm shutdown; chain was left running")
    stopped_chain = chain.stop(state)
    if stopped_chain.get("running") is not False:
        raise RuntimeError("Chain did not confirm shutdown; inspect stack status")
    return {"development_only": True, "success": True, "action": "stop", "state_preserved": True,
            "chain": stopped_chain, "services": stopped_services}


def start(repository, state, chain_port=None, bin_directory=None, broker_port=None, runtime_image=None, docker_socket=None, model_directory=None, model_binary=None):
    previous_chain = chain.status(state)
    previous_services = services.status(state)
    if previous_services.get("running") and not previous_chain.get("running"):
        raise RuntimeError("Services are still running without their chain; stop the stack before starting")
    started_chain = False
    stage = "chain"
    try:
        chain.start(repository, state, chain_port)
        started_chain = not previous_chain["running"]
        stage = "deployment"
        deployment_result = deployment.deploy(repository, state, offline=True)
        stage = "services"
        services.start(repository, state, bin_directory, broker_port, runtime_image, docker_socket, model_directory, model_binary)
        result = status(state)
        result.update(success=result["ready"], action="start", deployment=deployment_result)
        return result
    except OPERATION_ERRORS as error:
        cleanup = None
        if started_chain:
            try:
                if services.status(state).get("running") is False:
                    cleanup = chain.stop(state)
            except OPERATION_ERRORS as cleanup_error:
                cleanup = {"error": str(cleanup_error)}
        result = status(state)
        result.update(success=False, action="start", failed_stage=stage, error=str(error), cleanup=cleanup)
        return result


def execute(repository, state, action, chain_port=None, bin_directory=None, broker_port=None, runtime_image=None, docker_socket=None, model_directory=None, model_binary=None):
    if action in ("status", "doctor"):
        result = status(state)
        result.update(action=action, success=action == "status" or result["ready"])
        return result
    if action == "stop":
        return stop(state)
    if action == "restart":
        stop(state)
    if action in ("start", "restart"):
        result = start(repository, state, chain_port, bin_directory, broker_port, runtime_image, docker_socket, model_directory, model_binary)
        result["action"] = action
        return result
    raise ValueError("Unknown stack operation")


def logs(state):
    chain.logs(state)
    return services.logs(state)
