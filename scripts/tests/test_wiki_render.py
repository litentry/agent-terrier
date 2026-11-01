import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("wiki_render", ROOT / "scripts/render-wiki.py")
wiki_render = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wiki_render)
REVISION = "a" * 40


class WikiRenderTests(unittest.TestCase):
    def test_relative_links_are_validated_and_pinned_without_changing_code(self):
        tracked = {"docs/wiki/Home.md", "docs/wiki/local-chain.md", "docs/arch.md", "crates/example/lib.rs"}
        source = "Lead\n[chain](./local-chain.md#restart) [arch](../arch.md) [crate](../../crates/example)\n```md\n[example](./not-a-page.md)\n```\n"
        result = wiki_render.render_page("docs/wiki/Home.md", source, REVISION, tracked)
        self.assertIn("/wiki/local-chain#restart", result)
        self.assertIn("/blob/" + REVISION + "/docs/arch.md", result)
        self.assertIn("/tree/" + REVISION + "/crates/example", result)
        self.assertIn("[example](./not-a-page.md)", result)
        for target in ("./missing.md", "../../../outside", "/private/path", "./local-chain.md?raw=1"):
            with self.assertRaises(ValueError):
                wiki_render.render_page("docs/wiki/Home.md", f"[bad]({target})", REVISION, tracked)

    def test_source_rules_and_existing_output_refuse_publication(self):
        for source in ("# Home\n", "\n---\nkey: value\n"):
            with self.assertRaises(ValueError):
                wiki_render.render_page("docs/wiki/Home.md", source, REVISION, set())
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "never overwritten"):
                wiki_render.render(ROOT, REVISION, Path(temporary))
