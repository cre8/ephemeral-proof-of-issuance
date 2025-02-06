import type { ContainerVCPayload } from './container-vc-payload.js';

export interface DynamicCLVCPayload extends ContainerVCPayload {
  // list of entries
  entries: string;
}
