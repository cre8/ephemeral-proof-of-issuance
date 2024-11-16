import { JWTPayload } from 'jose';
import { HashFunctionName } from '../util.js';

export interface ContainerVCPayload extends JWTPayload {
  // The unique identifier of the vc.
  jti: string;

  // Hashing function. SHA-256 MUST be used.
  hashFunction: HashFunctionName;
}
