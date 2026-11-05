"""Real-chain, protected CLI and durable archive qualification without a browser."""
import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from qualify_local_chain import REPOSITORY, available_port
from qualify_local_login import request
from qualify_local_owner import LocalOwnerFixture
from qualify_local_services import LocalServicesQualification
from terrier_local import contracts, local_state


class LocalAuditQualification(LocalOwnerFixture):
    services = LocalServicesQualification.services
    stack = LocalServicesQualification.stack

    def test_archive_worker_receipts_owner_anchor_decode_restart_and_denials(self):
        with tempfile.TemporaryDirectory(prefix="terrier-audit-", dir="/tmp") as temporary:
            state = Path(temporary).resolve() / "state"
            try:
                self.invoke(state,"start","--port",str(available_port()))
                self.invoke(state,"deploy","--offline")
                started = self.services(state,"start")
                broker = started["services"]["broker"]["url"]
                archive = started["services"]["audit"]["url"]
                environment = contracts.tool_environment()
                environment["AGENT_TERRIER_STATE_DIR"] = str(state)
                sessions = {}
                for name in ("alice","bob"):
                    self.owner(state,"register","--name",name)
                    self.owner(state,"login","--name",name,"--broker-url",broker)
                    sessions[name] = local_state.read_json(state / "owners" / name / "session.json")["session"]["session_jwt"]
                token = (state / "services/audit/service.key").read_text().strip()

                def audit(action, *arguments, name="alice", payload=None, denial=None):
                    result = subprocess.run([sys.executable,str(REPOSITORY / "terrier"),"audit",action,"--name",name,*arguments],
                        env=environment,input=payload,capture_output=True,text=True,timeout=120)
                    for secret in [*sessions.values(),token]:
                        self.assertNotIn(secret,result.stdout + result.stderr)
                    if denial:
                        self.assertNotEqual(result.returncode,0)
                        self.assertIn(denial,result.stderr)
                        self.assertFalse(result.stdout)
                        return None
                    self.assertEqual(result.returncode,0,result.stderr)
                    return json.loads(result.stdout)

                database = state / "services/audit/archive.db"
                def snapshot():
                    with closing(sqlite3.connect(f"file:{database}?mode=ro",uri=True)) as connection:
                        return connection.execute("SELECT hash, operator, cbor FROM envelopes ORDER BY hash").fetchall()

                self.assertEqual(audit("list")["envelope_hashes"],[])
                stored = subprocess.run([sys.executable,str(REPOSITORY / "terrier"),"cred","store","example","--name","alice","--secret-stdin"],
                    env=environment,input="synthetic-audit-credential",capture_output=True,text=True,timeout=60)
                self.assertEqual(stored.returncode,0,stored.stderr)
                hashes = audit("list")["envelope_hashes"]
                self.assertTrue(hashes,"successful data operation produced no durable audit receipt")
                self.assertEqual(audit("list",name="bob")["envelope_hashes"],[])
                fetched = next(record for record in [audit("fetch","--hash",value) for value in hashes] if record["envelope"]["op_kind"] == 0)
                envelope_hash = fetched["envelope_hash"]
                self.assertEqual(fetched["envelope_hash"],envelope_hash)
                self.assertEqual(fetched["envelope"]["op_kind"],0)
                self.assertNotIn("synthetic-audit-credential",json.dumps(fetched))
                appended = audit("append", "--op-kind", "0", "--body-stdin", payload=json.dumps({"service":"synthetic-manual","payload_hash":"0x" + "12" * 32}))
                self.assertTrue(appended["stored"])
                self.assertFalse(appended["anchored"])
                self.assertEqual(audit("fetch", "--hash", appended["envelope_hash"])["envelope"]["op_body"]["service"], "synthetic-manual")
                indexed = audit("list")["envelope_hashes"]
                first = audit("list", "--limit", "1")
                second = audit("list", "--limit", "1", "--cursor", first["next_cursor"])
                self.assertEqual(first["envelope_hashes"] + second["envelope_hashes"], indexed[:2])
                self.assertEqual(request(broker + "/v1/audit/envelopes?limit=0", bearer=sessions["alice"])[0],400)
                self.assertEqual(request(broker + "/v1/audit/envelopes?cursor=invalid", bearer=sessions["alice"])[0],400)
                before = snapshot()
                audit("fetch","--hash",envelope_hash,name="bob",denial="HTTP 404")
                self.assertEqual(request(broker + "/v1/audit/envelope/" + envelope_hash)[0],401)
                self.assertEqual(request(broker + "/v1/audit/envelope/" + envelope_hash,bearer="invalid-session")[0],401)
                self.assertEqual(request(archive + "/v1/audit/envelope/" + envelope_hash)[0],401)
                self.assertEqual(request(archive + "/v1/audit/append/v2", fetched["envelope"],"incorrect-token")[0],401)
                self.assertEqual(request(broker + "/v1/audit/append/v2", fetched["envelope"],sessions["bob"])[0],403)
                self.assertEqual(snapshot(),before,"refused requests changed archived records")
                audit("append","--op-kind","255","--body-stdin",payload="{}",denial="unknown audit")
                self.assertEqual(snapshot(),before)
                anchor = audit("anchor","--hash",envelope_hash)
                self.assertTrue(anchor["anchored"] and anchor["verified"])
                from terrier_local import chain
                block = chain.rpc(started["chain_rpc"] if "chain_rpc" in started else local_state.read_json(state / "chain-profile.json")["rpc"]["http"],"eth_blockNumber")
                journal_path = state / "owners/alice/audit-anchors" / (envelope_hash + ".json")
                journal = local_state.read_json(journal_path)
                self.assertEqual(journal["plan"]["build"]["user_op"]["signature"],"0x")
                journal["transaction_hash"] = None
                local_state.write_json(journal_path,journal)
                restored = audit("anchor","--hash",envelope_hash)
                self.assertEqual(restored["transaction_hash"],anchor["transaction_hash"])
                self.assertTrue(restored["recovered"])
                self.assertEqual(chain.rpc(local_state.read_json(state / "chain-profile.json")["rpc"]["http"],"eth_blockNumber"),block)
                page = audit("recent")
                event = next(record for record in page["records"] if record["envelope_hash"] == envelope_hash)
                decoded = audit("decode","--id",event["event"]["id"])
                self.assertFalse(decoded["synthesized"])
                decoded_envelope = dict(decoded["envelope"])
                self.assertTrue(decoded_envelope.pop("canonical_cbor").startswith("0x"))
                self.assertEqual(decoded_envelope,fetched["envelope"])
                self.assertTrue(self.stack(state,"restart")["ready"])
                self.assertEqual(audit("fetch","--hash",envelope_hash),fetched)
                self.assertEqual(audit("decode","--id",event["event"]["id"])["envelope"],decoded["envelope"])
                self.assertEqual(snapshot(),before,"restart changed immutable audit records")
                self.assertEqual((state / "services/audit/service.key").read_text().strip(),token)
            finally:
                self.services(state,"stop")
                self.invoke(state,"stop")


if __name__ == "__main__":
    unittest.main(defaultTest="LocalAuditQualification")
