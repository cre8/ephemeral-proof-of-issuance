import type { HMACFunctionName, HashFunctionName } from './util.js';

// recommened value from ebsi
export const DEFAULT_EPOCH = 3600;
//TODO: instead of a HMAC, check if there are similar approaches that are more efficient
// recommened value from ebsi
export const DEFAULT_HMAC_FUNCTION: HMACFunctionName = 'SHA-256';
// recommened value from ebsi
export const DEFAULT_HASH_FUNCTION: HashFunctionName = 'SHA-256';
