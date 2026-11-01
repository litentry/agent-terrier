import { describe, expect, it } from 'vitest';
import { describeError, isExpired, pairingUri, sessionFromBroker, sessionStale } from '../pairing';

describe('pairing helpers', () => {
  it('a pending answer yields no session; a bound one carries the two omnis', () => {
    expect(sessionFromBroker({ status: 'pending' } as never, 100)).toBeNull();
    const s = sessionFromBroker(
      { session_jwt: 'j1', actor_omni: '0xchild', operator_omni: '0xop', device_key_hash: '0xdkh', label: 'kitchen' },
      100,
    );
    expect(s).toEqual({
      session_jwt: 'j1',
      actor_omni: '0xchild',
      operator_omni: '0xop',
      device_key_hash: '0xdkh',
      label: 'kitchen',
      minted_at: 100,
    });
    expect(sessionStale(s!, 100 + 3 * 3600)).toBe(false);
    expect(sessionStale(s!, 100 + 4 * 3600)).toBe(true);
  });

  it('expiry and error classification', () => {
    expect(isExpired(0, 999)).toBe(false);
    expect(isExpired(500, 499)).toBe(false);
    expect(isExpired(500, 500)).toBe(true);
    expect(describeError(new Error('broker rejected /v1/agent/resolve: status=401 body=…'))).toMatchObject({
      status: 401,
      retryable: false,
    });
    expect(describeError('transport: POST /v1/agent/pairing/poll: fetch failed')).toMatchObject({
      status: null,
      retryable: true,
    });
    expect(describeError(new Error('status=503 body=x')).retryable).toBe(true);
  });

  it('the QR carries the code, label and feed', () => {
    expect(pairingUri('K7QX-2', 'kitchen-display', 'kitchen-display')).toBe(
      'agentkeys-pair://claim?code=K7QX-2&label=kitchen-display&feed=kitchen-display',
    );
  });
});
