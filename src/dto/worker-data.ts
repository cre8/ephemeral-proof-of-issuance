import { HMACFunctionName, HashFunctionName } from '../util.js';
import { VcStatus } from './vc-status.js';

export interface WorkerData {
  /**
   * Elements that should be hashed
   */
  elements: VcStatus[];

  /**
   * The duration of the list
   */
  duration: string;

  /**
   * Used hash function
   */
  hashFunction: HashFunctionName;

  /**
   * Used hmac function.
   */
  hmacFunction: HMACFunctionName;
}
