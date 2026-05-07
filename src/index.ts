export { anonymizeIp } from './anonymize.js';
export type {
  AnonymizationLevel,
  AnonymizeOptions,
  SaltRotation,
} from './anonymize.js';

export { sendUmamiEvent, resolveConfigFromEnv } from './send.js';
export type {
  UmamiCloudConfig,
  UmamiSelfHostedConfig,
  UmamiConfig,
  UmamiPayload,
  SendOptions,
  SendResult,
} from './send.js';

export { createCounterHandler, extractClientIp } from './handler.js';
export type {
  CounterHandlerOptions,
  CounterHandlerInput,
  CounterRequestBody,
  CounterResult,
} from './handler.js';
