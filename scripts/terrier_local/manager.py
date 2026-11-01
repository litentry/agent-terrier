import sys

MENU = (("Status", "status"), ("Check health", "doctor"), ("Start", "start"),
        ("Restart, keeping data", "restart"), ("Show private logs", "logs"), ("Stop, keeping data", "stop"))


def run(dispatch, input_stream=None, output_stream=None):
    source = input_stream if input_stream is not None else sys.stdin
    destination = output_stream if output_stream is not None else sys.stdout
    if not source.isatty() or not destination.isatty():
        raise ValueError("The local manager requires a terminal; use terrier stack commands in scripts")
    print("Agent Terrier local manager — chain and backend services", file=destination)
    print("Uses the current local state and existing configuration. Model runner and website are separate.", file=destination)
    while True:
        for number, (label, _) in enumerate(MENU, 1):
            print(f"{number}. {label}", file=destination)
        print("q. Quit (leave services running)\nChoose: ", end="", file=destination, flush=True)
        selected = source.readline().strip()
        if not selected or selected.lower() == "q":
            return 0
        if selected not in {str(number) for number in range(1, len(MENU) + 1)}:
            print("Choose a listed number or q.", file=destination)
            continue
        action = MENU[int(selected) - 1][1]
        exit_code = dispatch(["stack", action])
        if exit_code:
            print("The operation did not complete. Inspect the reported error before retrying.", file=destination)
