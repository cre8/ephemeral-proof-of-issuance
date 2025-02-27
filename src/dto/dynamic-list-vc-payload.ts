import type { ContainerVCPayload } from './container-vc-payload.js';

export interface DynamicListVCPayload extends ContainerVCPayload {
  // list of entries
  entries: string;
}
