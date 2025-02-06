import type { JWTPayload } from 'jose';
import type { HashFunctionName } from '../util.js';

export interface ContainerVCPayload extends JWTPayload {
  // The unique identifier of the vc.
  jti: string;

  // Hashing function. SHA-256 MUST be used.
  hashFunction: HashFunctionName;
}
