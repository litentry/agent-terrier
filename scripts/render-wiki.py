#!/usr/bin/env python3
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
from urllib.parse import quote, unquote, urlsplit

PUBLIC_REPOSITORY = "https://github.com/litentry/agent-terrier"
LINK = re.compile(r"(!?\[[^\]\n]*\]\()([^\s)]+)(\))")


def read_revision(repository, revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Use an exact public commit ID")

    def jj(*arguments):
        result = subprocess.run(["jj", "--ignore-working-copy", *arguments], cwd=repository,
            capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError("Could not read the selected public revision")
        return result.stdout

    if jj("log", "-r", revision, "--no-graph", "-T", "commit_id").strip() != revision:
        raise ValueError("Revision did not resolve to the exact requested commit")
    tracked = set(jj("file", "list", "-r", revision).splitlines())
    names = sorted(name for name in tracked if name.startswith("docs/wiki/") and name.endswith(".md"))
    if "docs/wiki/Home.md" not in names or not names:
        raise ValueError("The selected revision must contain the canonical wiki Home page")
    if any(len(PurePosixPath(name).parts) != 3 for name in names):
        raise ValueError("Wiki pages must be direct Markdown children of docs/wiki")
    pages = {name: jj("file", "show", "-r", revision, name) for name in names}
    return tracked, pages


def render_page(name, contents, revision, tracked):
    first = next((line.strip() for line in contents.splitlines() if line.strip()), "")
    if first == "---" or first.startswith("# "):
        raise ValueError("Wiki source must not begin with frontmatter or a redundant title")

    def rewrite(match):
        target = match[2]
        location = urlsplit(target)
        if location.scheme or location.netloc or target.startswith("#"):
            return match[0]
        if location.query or target.startswith("/"):
            raise ValueError("Relative wiki links must use repository paths without queries")
        resolved = posixpath.normpath(posixpath.join("docs/wiki", unquote(location.path)))
        if resolved.startswith("../") or resolved not in tracked and not any(item.startswith(resolved + "/") for item in tracked):
            raise ValueError(f"Unresolved public link in {PurePosixPath(name).name}")
        if resolved.startswith("docs/wiki/") and resolved.endswith(".md"):
            rendered = PUBLIC_REPOSITORY + "/wiki/" + quote(PurePosixPath(resolved).stem)
        else:
            kind = "blob" if resolved in tracked else "tree"
            rendered = f"{PUBLIC_REPOSITORY}/{kind}/{revision}/" + quote(resolved, safe="/")
        if location.fragment:
            rendered += "#" + location.fragment
        return match[1] + rendered + match[3]

    segments = re.split(r"(^```[^\n]*\n.*?^```[^\n]*(?:\n|$))", contents, flags=re.MULTILINE | re.DOTALL)
    rendered = "".join(segment if index % 2 else LINK.sub(rewrite, segment) for index, segment in enumerate(segments))
    return rendered.rstrip() + f"\n\n---\n\n[Canonical source]({PUBLIC_REPOSITORY}/blob/{revision}/{name}) · revision `{revision}`.\n"


def render(repository, revision, destination):
    repository = repository.resolve()
    destination = destination.expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("Use a new output directory; existing files are never overwritten")
    destination = destination.parent.resolve(strict=True) / destination.name
    if destination == repository or repository in destination.parents:
        raise ValueError("Generated wiki output must be outside the source checkout")
    tracked, pages = read_revision(repository, revision)
    rendered = {PurePosixPath(name).name: render_page(name, contents, revision, tracked) for name, contents in pages.items()}
    destination.mkdir(mode=0o700)
    for name, contents in rendered.items():
        (destination / name).write_text(contents)
    manifest = {"source_repository": PUBLIC_REPOSITORY, "source_revision": revision,
                "pages": {name: hashlib.sha256(contents.encode()).hexdigest() for name, contents in rendered.items()}}
    (destination / "_publication.json").write_text(json.dumps(manifest, indent=2) + "\n")
    specification = importlib.util.spec_from_file_location("public_contents", repository / "scripts/check-public.py")
    scanner = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(scanner)
    report = scanner.inspect_tree(destination)
    if report["findings"]:
        raise ValueError("Rendered wiki failed privacy review; do not publish the output")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Render reviewed public wiki pages from an exact revision; no network writes")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        manifest = render(Path(__file__).resolve().parents[1], arguments.revision, arguments.output)
        print(json.dumps({"source_revision": manifest["source_revision"], "pages": len(manifest["pages"]), "privacy": "passed"}))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"wiki: {error}\n")
