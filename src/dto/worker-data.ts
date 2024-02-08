import { HashFunction } from '../util';
import { VcStatus } from './vc-status';

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
  hashFunction: HashFunction;
}
