import type { HostedSignerApproval } from './generated/HostedSignerApproval';
import type { HostedSignerChallenge } from './generated/HostedSignerChallenge';
import type { HostedSignerStartRequest } from './generated/HostedSignerStartRequest';
import { signHostedEnrollment, type HostedBrowserIdentity } from './hostedIdentity';
import { getAssertionOverHash } from './webauthn';

export async function buildBrowserApproval(
  identity: HostedBrowserIdentity,
  start: (request: HostedSignerStartRequest) => Promise<HostedSignerChallenge>,
): Promise<HostedSignerApproval> {
  const requested: HostedSignerStartRequest = {
    credential_id: identity.credentialId, public_key_x: identity.publicKeyX, public_key_y: identity.publicKeyY,
    device_key_hash: identity.deviceKeyHash, origin: location.origin, rp_id: location.hostname,
  };
  const enrollment = await start(requested);
  if (enrollment.intent.operator_omni.replace(/^0x/, '').toLowerCase() !== identity.omni.replace(/^0x/, '').toLowerCase()
    || Object.entries(requested).some(([field, value]) => enrollment.intent[field as keyof HostedSignerStartRequest] !== value)) {
    throw new Error('The approval request differs from this browser identity or website. No proof was signed.');
  }
  const proof = await getAssertionOverHash(enrollment.challenge, [identity.credentialId]);
  const device_proof = await signHostedEnrollment(identity, enrollment.challenge);
  return { enrollment, proof, device_proof };
}
