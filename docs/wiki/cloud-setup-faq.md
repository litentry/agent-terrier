# Cloud setup — FAQ

Troubleshooting + edge cases for the two cloud-side operator docs:

- [`docs/cloud-bootstrap.md`](https://github.com/litentry/agentKeys/blob/main/docs/cloud-bootstrap.md) — first-time provisioning (per account or per cloud provider).
- [`docs/cloud-bootstrap.md`](https://github.com/litentry/agentKeys/blob/main/docs/cloud-bootstrap.md) — ongoing OIDC federation + broker-host re-deploys.

Use ⌘F to find your error.

## Q. `setup-broker-host.sh` says "BROKER_OIDC_ISSUER mismatch" on re-run

The script auto-detects an existing systemd unit and reads `Environment=` lines to decide bootstrap-vs-upgrade. If you ran with a different `--issuer-url` previously and the AWS OIDC provider was already registered for the old URL, the new run refuses.

**Fix:** decide which URL is canonical. AWS validates the OIDC issuer URL byte-for-byte against the JWT `iss` claim, so the issuer URL is effectively immutable once the IAM trust policy is built. Either:
- Re-run with the OLD `--issuer-url` (the trust policy already matches).
- Or delete the OIDC provider, redo §4 from cloud-bootstrap.md, and re-run with the NEW URL.

## Q. nginx 502 after a fresh `setup-broker-host.sh` run

systemd may have started the broker before nginx finished its first `systemctl reload`. Two-step fix:

```bash
sudo systemctl status agentkeys-broker          # → active (running)
sudo systemctl restart nginx                    # picks up the new vhost
curl -sf https://${BROKER_HOST}/healthz         # → 200
```

If the broker itself is failing to boot, `journalctl -u agentkeys-broker -n 50` is authoritative.

## Q. `verify_sender_ready` precheck fails at broker boot

The broker calls SES `GetEmailIdentity` on `BROKER_EMAIL_FROM_ADDRESS` at startup. If the SES domain identity isn't verified yet, boot refuses. Run [`scripts/ses-verify-sender.sh`](https://github.com/litentry/agentKeys/blob/main/scripts/ses-verify-sender.sh) and wait for the DKIM tokens to propagate (5–30 min typical), then restart the broker.

## Q. `aws iam create-open-id-connect-provider` returns `EntityAlreadyExistsException`

The OIDC provider already exists. Verify with:

```bash
aws iam list-open-id-connect-providers \
  | jq -r '.OpenIDConnectProviderList[].Arn' \
  | grep "${BROKER_HOST}"
```

If the ARN is correct, you're done — the trust policy and bucket policy from §4.3/§4.4 are the only steps that remain.

## Q. `AccessDenied` from S3 even though the role + bucket policy look right

Three things almost always:

1. The role's **inline policy** still has the broad-bucket grant from §3.5 — strip it via §4.4.1.
2. The bucket policy's `s3:prefix` condition needs the `${aws:PrincipalTag/agentkeys_actor_omni}` interpolation to be lowercased — addresses are case-sensitive in policy string comparisons.
3. `s3:ListBucket` needs the `s3:prefix=bots/${PrincipalTag}/<class>/*` condition in a separate statement (the v3 split-statement bucket policy from codex P2). Listing the bucket root without that condition always returns AccessDenied.

CloudTrail's `Decision` field tells you which statement evaluated.

## Q. Per-profile default region trap (real 2026-05-12 incident)

`agentkeys-admin` defaults to `us-west-2`; `agentkeys-broker` / `agentkeys-daemon` default to `us-east-1`. Every regional CLI call must pass `--region "$REGION"` explicitly. The CLAUDE.md "Per-profile default region is NOT uniform" section covers this in detail.

## Q. Cert renewal failed silently — workflow turned red overnight

certbot renewals run on a 90-day cadence. If they fail (often: rate limit, DNS-01 hiccup, port 80 firewall block), AWS stops trusting the OIDC issuer (TLS chain breaks). Symptoms:

- `harness-e2e` CI job fails on the first `curl https://${BROKER_HOST}` with a TLS error.
- `journalctl -u certbot-renew` shows the failure reason.

**Recovery:** rerun `sudo certbot renew --force-renewal` (works for transient rate-limit issues), or fix the DNS / firewall and re-run. The broker doesn't need to restart — nginx reloads automatically.

## Q. Switching AWS accounts for the test instance

Same-account is fine — isolation comes from the `-test` suffix, not from the AWS account boundary. If you want hard account isolation, every reference to `${ACCOUNT_ID}` in cloud-bootstrap.md becomes `${TEST_ACCOUNT_ID}`, including the role ARN that the broker assumes via OIDC. The setup-broker-host.sh script accepts `--account-id` to point at a different account.

## Q. Tencent Cloud port?

§2.2 of cloud-bootstrap.md sketches SimpleDM + COS as the swap-in at the §3+ boundary. The boundary is real — DNS + inbound mail are the only AWS-specific layers; everything from `agentkeys-data-role` onward is provider-agnostic in shape, with COS providing S3-compatible PutObject/GetObject and Tencent's IAM providing OIDC federation. Real port work is tracked separately.

## Q. Can I run the broker without nginx?

Yes — `setup-broker-host.sh --without-nginx --without-certbot` skips both. You're then responsible for TLS termination upstream (CloudFront, ALB, custom reverse proxy). AWS still needs to fetch the OIDC discovery + JWKS over public TLS, so whatever fronts the broker must serve `https://${BROKER_HOST}/.well-known/*` with a valid leaf cert.

## Q. The systemd unit was hand-edited and now setup-broker-host.sh refuses

Per CLAUDE.md "Remote broker host (single entry point)" — don't hand-edit. To recover:

```bash
sudo systemctl stop agentkeys-broker
sudo rm /etc/systemd/system/agentkeys-broker.service
sudo systemctl daemon-reload
sudo bash scripts/setup-broker-host.sh --yes
```

The script rewrites the unit clean. If you had a legitimately custom field, add a `--*-host` or `--cred-mode` flag to the script and re-run — that's how all per-host overrides ship.

## Related

- Operator runbook: [docs/cloud-bootstrap.md](https://github.com/litentry/agentKeys/blob/main/docs/cloud-bootstrap.md)
- Single entry point: [scripts/setup-broker-host.sh](https://github.com/litentry/agentKeys/blob/main/scripts/setup-broker-host.sh)
- Heima chain FAQ: [heima-setup-faq](./heima-setup-faq.md)
- CI FAQ: [ci-setup-faq](./ci-setup-faq.md)
