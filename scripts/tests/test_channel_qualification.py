import base64
import json
import unittest

from qualify_local_agents import completed_reply, latest_lifecycle


class ChannelQualificationTests(unittest.TestCase):
    def event(self, kind, body, **fields):
        return dict(kind=kind, direction="out", body=base64.b64encode(body.encode()).decode(), **fields)

    def test_latest_lifecycle_must_finish_startup(self):
        ready = self.event("lifecycle", json.dumps({"stage": "ready"}))
        restoring = self.event("lifecycle", json.dumps({"stage": "restoring"}))
        self.assertEqual(latest_lifecycle([ready, restoring]), "restoring")
        self.assertEqual(latest_lifecycle([restoring, ready]), "ready")
        self.assertIsNone(latest_lifecycle([self.event("text", "ready")]))
        self.assertIsNone(latest_lifecycle([dict(ready, direction="in")]))

    def test_explicit_degraded_status_is_not_reported_as_ready(self):
        degraded = self.event("lifecycle", json.dumps({"stage": "degraded"}))
        self.assertEqual(latest_lifecycle([degraded]), "degraded")
        with self.assertRaises(ValueError):
            latest_lifecycle([self.event("lifecycle", "not-json")])

    def test_only_completed_correlated_text_proves_a_reply(self):
        reply = self.event("text", "unique-marker", correlation="request-1")
        self.assertTrue(completed_reply(reply, "request-1", "unique-marker"))
        for changed in [dict(reply, correlation="other-request"), dict(reply, direction="in"),
                        dict(reply, kind="doc"), dict(reply, partial=True), dict(reply, body="")]:
            self.assertFalse(completed_reply(changed, "request-1", "unique-marker"))
