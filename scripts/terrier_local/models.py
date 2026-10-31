import json
import subprocess

from . import contracts, owner


def run(repository, action, base_url=None, chat_model=None, embedding_model=None):
    if action == "config" and any((base_url, chat_model, embedding_model)):
        raise ValueError("Model configuration display does not accept probe overrides")
    arguments = [str(owner.executable(repository)), "models", action]
    for flag, value in [("--base-url", base_url), ("--chat-model", chat_model),
                        ("--embedding-model", embedding_model)]:
        if value:
            arguments.extend([flag, value])
    result = subprocess.run(arguments, env=contracts.tool_environment(),
                            capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout)
