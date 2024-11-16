import { ContainerVCPayload } from './container-vc-payload.js';

export interface DynamicCRLVCPayload extends ContainerVCPayload {
  // list of entries
  entries: string[];
}
