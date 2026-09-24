/** @module @agentkeys/dsh-suite — re-exports only; plugins mount via the
 *  subpaths (`@agentkeys/dsh-suite/guard`, `/answerer`, `/actions`, …).
 *  Deliberately NO default export anywhere (dsh postmortem 0001). */
export {
  advertisedGrantPrefix,
  classifyTool,
  DEFAULT_BASELINE,
  DEFAULT_HIDDEN_TOOLS,
  DEFAULT_TOOL_CLASSES,
  holdsGrantWithPrefix,
  OPENVIKING_TOOL_PATTERNS,
  PROPOSE_ACTION,
  PROPOSE_SERVICE_PREFIX,
  PUBLISH_ACTION,
  PUBLISH_SERVICE_PREFIX,
  registerAdvertised,
} from './mapping.js';
export type { MappingConfig, ToolVerdict } from './mapping.js';
export { DaemonClient, DaemonError, DEFAULT_DAEMON_URL, reasonOf } from './daemon-client.js';
export type { DaemonClientOptions } from './daemon-client.js';
export { DEFAULT_GRANTS_URL, GrantsCache, consumeApprovedCall, recordApprovedCall } from './grants.js';
export type { GrantView, GrantsConfig } from './grants.js';
export { decide } from './guard.js';
export { ACTIONS_PATH, callBody, missingRequired, parseAdvertised, toolParameters, toReceipt, whenRegistered } from './actions.js';
export type { AdvertisedAction, AdvertisedParam, Receipt } from './actions.js';
export { answer, DEFAULT_PROPOSE_URL, maybePropose, PROPOSE_THROTTLE_MS, proposeBody, proposeKey, ProposeThrottle } from './answerer.js';
export type { ProposeOutcome } from './answerer.js';
export { AgentKeysCredentialProvider, DEFAULT_CREDENTIAL_URL } from './credentials.js';
export { approvalRow, AuditSink, OP_KIND_RUNTIME_APPROVAL, OP_KIND_RUNTIME_TOOL_RESULT, toolResultRow } from './audit.js';
export {
  chatReply,
  doneFrame,
  encodeFrame,
  errorFrame,
  healthzBody,
  thinkingFrame,
  tokenFrame,
  toolFrame,
  toolStartFrame,
  shouldEmitToolFrame,
} from './bridge-frames.js';
export type { BridgeFrame, ChatReply, HealthzBody } from './bridge-frames.js';
export { TurnStreamer } from './bridge-stream.js';
export { exportHome, homeBytes, importHome, isExcludedPath, relPathOk, MGMT_SNAPSHOT_MAX_BYTES } from './bridge-mgmt.js';
export type { SnapshotDoc, SnapshotFile, ImportOutcome } from './bridge-mgmt.js';
export { ALLOWED_POLICIES, standingAllowViolation } from './invariant.js';
