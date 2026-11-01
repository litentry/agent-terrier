`docs/wiki` is the sole source for this public wiki. Pages are freshly authored from reviewed public behavior. Do not copy inherited operational documents, captured logs, wallet configuration or personal screenshots into this directory.

## Review and render

Edit canonical pages in a pull request. Pages have no YAML frontmatter and no redundant leading H1. Use relative links to other source pages and repository files; the renderer checks those targets and rewrites them for GitHub Wiki. Repository-file links pin the selected source commit. Code blocks are preserved.

Local, in the public checkout, before publishing:

```sh
bash scripts/utils/lint-wiki.sh
python3 scripts/check-public.py
python3 scripts/render-wiki.py \
  --revision "${AGENT_TERRIER_WIKI_REVISION:?Set the reviewed public commit ID}" \
  --output "${AGENT_TERRIER_WIKI_OUTPUT:?Choose a new directory outside the checkout}"
```

The renderer uses `jj` to read exactly that revision, not uncommitted files. It refuses missing local link targets, an existing output directory, output inside source, and privacy findings. `_publication.json` records the public revision and each generated page hash. Review the exact output before sending it to the repository's own wiki. The scanner is an additional check, not proof that arbitrary private information is absent.

## Publish

Initialize an empty repository wiki by creating its first Home page through GitHub's wiki interface, using the reviewed canonical Home content. Then use a separate owned wiki checkout. Local, outside the source checkout:

```sh
jj git clone https://github.com/litentry/agent-terrier.wiki.git \
  "${AGENT_TERRIER_WIKI_CHECKOUT:?Choose a new wiki checkout}"
```

Review the wiki checkout for unrelated changes. Copy only the reviewed rendered Markdown pages and `_publication.json` into that checkout, preserving any unrelated content. Inspect the diff, record the publication and push its default bookmark with `jj`. Verify Home, an internal page link and a revision-pinned source link in the browser. Do not edit published pages as a second source of truth; change `docs/wiki` and regenerate.

Publication is an explicit maintainer operation using existing authorized access. No personal token, private credential or private repository is required by the public source. Automatic wiki scheduling and independent full documentation walkthrough remain release work; the renderer itself performs no network writes.
