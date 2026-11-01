// The route tab's read of `GET /v1/master/gateway/router`. The console and the
// contact gate deploy separately (the console from a laptop checkout, the gate
// on the broker host), so the console must also read an OLDER gate: one from
// before the Kev / Jev switch (#749) answers without `models`, `compare`,
// `default_model` and the per-turn `compared`, and reports its one model
// server as `upstream`. Normalize here, at the boundary, so the page never
// reads a field the gate did not send.
import type { DecisionServerReport } from '@/lib/generated/DecisionServerReport';
import type { GatewayRouterView } from '@/lib/generated/GatewayRouterView';
import type { RouterExchange } from '@/lib/generated/RouterExchange';

/** What a contact gate of any version sends: the switch's fields may be absent. */
export type RouterViewWire = Omit<GatewayRouterView, 'models' | 'compare' | 'default_model' | 'recent'> & {
  models?: GatewayRouterView['models'];
  compare?: GatewayRouterView['compare'];
  default_model?: GatewayRouterView['default_model'];
  recent?: Array<Omit<RouterExchange, 'id' | 'compared'> & Partial<Pick<RouterExchange, 'id' | 'compared'>>>;
  /** A pre-switch gate's one model server: `base_url`, `status`, `models`, or `error`. */
  upstream?: unknown;
};

export type RouterViewRead = {
  view: GatewayRouterView;
  /** The gate predates the switch: no model list, no compare. */
  legacy: boolean;
  /** A pre-switch gate's model server, in the report shape the cards use. */
  legacyServer?: DecisionServerReport;
};

export function normalizeRouterView(raw: RouterViewWire): RouterViewRead {
  const { upstream, models, compare, default_model, recent, ...rest } = raw;
  const legacy = !Array.isArray(models);
  return {
    legacy,
    legacyServer: legacy ? legacyServerOf(upstream) : undefined,
    view: {
      ...rest,
      models: models ?? [],
      compare: compare ?? false,
      default_model: default_model ?? raw.model,
      recent: (recent ?? []).map((x, i) => ({ ...x, id: x.id ?? i, compared: x.compared ?? [] })),
    },
  };
}

function legacyServerOf(u: unknown): DecisionServerReport | undefined {
  if (!u || typeof u !== 'object' || Array.isArray(u)) return undefined;
  const o = u as Record<string, unknown>;
  return {
    // A pre-switch gate does not say whether its model gate holds the key;
    // its `error` (or a non-2xx status) is what the card shows.
    configured: true,
    base_url: typeof o.base_url === 'string' ? o.base_url : undefined,
    status: typeof o.status === 'number' ? o.status : undefined,
    models: o.models ?? undefined,
    error: typeof o.error === 'string' ? o.error : undefined,
  };
}
