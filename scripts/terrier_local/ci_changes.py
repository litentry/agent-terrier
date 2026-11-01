import json
import os
import re
import urllib.error
import urllib.request

from .affected import validate_paths

API_ROOT = "https://api.github.com"
MAX_FILES = 3000
PAGE_SIZE = 100
RESPONSE_LIMIT = 32 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def api_reader(token):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def read(path):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10",
                   "User-Agent": "agent-terrier-ci"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(API_ROOT + path, headers=headers)
        try:
            with opener.open(request, timeout=30) as response:
                contents = response.read(RESPONSE_LIMIT + 1)
        except (OSError, urllib.error.URLError):
            raise RuntimeError("GitHub changed-file request failed; no partial selection was accepted") from None
        if len(contents) > RESPONSE_LIMIT:
            raise ValueError("GitHub changed-file response exceeds the bounded input size")
        try:
            return json.loads(contents)
        except ValueError:
            raise ValueError("GitHub returned an invalid changed-file response") from None

    return read


def coordinates(pull_request):
    return (pull_request["base"]["sha"], pull_request["head"]["sha"])


def collect(event, repository, revision, read):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid public repository name")
    pull_request = event["pull_request"]
    number = event["number"]
    expected = coordinates(pull_request)
    if (type(number) is not int or number <= 0 or pull_request["base"]["repo"]["full_name"] != repository
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
                   for value in (*expected, revision))):
        raise ValueError("Invalid pull-request revision coordinates")
    prefix = f"/repos/{repository}"
    commit = read(f"{prefix}/git/commits/{revision}")
    parents = [parent["sha"] for parent in commit["parents"]]
    if commit["sha"] != revision or parents != list(expected):
        raise ValueError("Checked revision is not the event's exact base/head merge; refresh the PR branch and start a new run")
    endpoint = f"{prefix}/pulls/{number}"
    before = read(endpoint)
    count = before["changed_files"]
    if coordinates(before) != expected:
        raise ValueError("Pull-request revisions changed before file collection; refresh the PR branch and start a new run")
    if type(count) is not int or not 0 < count <= MAX_FILES:
        raise ValueError("Pull request has no files or exceeds the API's complete-file limit; split the change")
    entries = []
    for page in range(1, (count + PAGE_SIZE - 1) // PAGE_SIZE + 1):
        batch = read(f"{endpoint}/files?per_page={PAGE_SIZE}&page={page}")
        expected_size = min(PAGE_SIZE, count - len(entries))
        if not isinstance(batch, list) or len(batch) != expected_size:
            raise ValueError("Incomplete changed-file page; no partial selection was accepted")
        entries.extend(batch)
    filenames, changed_paths = set(), []
    for entry in entries:
        filename = entry["filename"]
        validate_paths([filename])
        if filename in filenames:
            raise ValueError("Duplicate changed-file entry; no partial selection was accepted")
        filenames.add(filename)
        changed_paths.append(filename)
        if entry["status"] == "renamed":
            changed_paths.append(entry["previous_filename"])
        elif entry["status"] not in {"added", "removed", "modified", "copied", "changed", "unchanged"}:
            raise ValueError("Unsupported changed-file status")
    validate_paths(changed_paths)
    after = read(endpoint)
    if coordinates(after) != expected or after["changed_files"] != count:
        raise ValueError("Pull request changed during file collection; refresh the PR branch and start a new run")
    return sorted(set(changed_paths))


def write_paths(destination, paths, repository):
    destination = destination.expanduser().absolute()
    if destination.is_symlink():
        raise ValueError("Changed-file output must not be a symlink")
    destination = destination.parent.resolve(strict=True) / destination.name
    repository = repository.resolve()
    if destination == repository or repository in destination.parents:
        raise ValueError("Changed-file output must be outside the checkout")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(paths, output)
        output.write("\n")
