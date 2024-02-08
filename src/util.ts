import { JWK, SignJWT, importJWK } from 'jose';
import { getRandomValues, subtle } from 'crypto';
import { DynamicSLBloomFilter2023VC } from './dto/dynamic-sl-bloom-filter-2023';
import murmurhash from 'murmurhash';

/**
 * Possible hash functions
 */
export type HashFunction = 'SHA-256' | 'MurmurHash3';

/**
 * Creates a secret
 * @returns
 */
export function createSecret() {
  return getRandomValues(new Uint8Array(32)).toString();
}

/**
 * Hash a value where the SHA-256 algorithm is used. In case of multiple inputs, they are concatenated.
 * @param inputs The inputs to hash
 * @param usedFunction The hash function to use
 */
export async function hash(
  inputs: string[],
  usedFunction: HashFunction = 'SHA-256'
): Promise<string> {
  switch (usedFunction) {
    case 'MurmurHash3':
      return Promise.resolve(murmurhash.v3(inputs.join('')).toString());
    case 'SHA-256':
      return subtle
        .digest('SHA-256', new TextEncoder().encode(inputs.join('')))
        .then((res) => base64Encode(res));
    default:
      throw Error(`Hash function ${usedFunction} not supported`);
  }
}

/**
 * Hash-based message authentication code function HMAC-SHA256 MUST be used. Use the subtle crypto API to compute the HMAC.
 * @returns The HMAC value as a hex string.
 */
export async function hmac(value: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const algorithm = { name: 'HMAC', hash: 'SHA-256' };
  return subtle
    .importKey('raw', enc.encode(secret), algorithm, false, ['sign', 'verify'])
    .then((key) =>
      subtle
        .sign(algorithm.name, key, enc.encode(value))
        .then((signature) => base64Encode(signature))
    );
}

/**
 * Encodes an arraybuffer to a base64 string.
 * @param buffer
 * @returns
 */
export function base64Encode(buffer: ArrayBuffer): string {
  if (typeof Buffer === 'undefined') {
    return window.btoa(String.fromCharCode(...new Uint8Array(buffer)));
  } else {
    return Buffer.from(buffer).toString('base64');
  }
}

/**
 * Decodes a base64 string to an arraybuffer.
 */
export function base64Decode(encoded: string): ArrayBuffer {
  if (typeof Buffer === 'undefined') {
    return Uint8Array.from(window.atob(encoded), (c) => c.charCodeAt(0));
  } else {
    return Buffer.from(encoded, 'base64');
  }
}

/**
 * Signs a vc with the given jwk.
 * @param jwk
 * @param vc
 * @param alg
 * @returns
 */
export async function signVc(
  jwk: JWK,
  vc: DynamicSLBloomFilter2023VC,
  alg: string
) {
  const key = await importJWK(jwk);
  // TODO check if all values are included https://www.w3.org/TR/vc-data-model/#jwt-decoding
  return new SignJWT({ vc })
    .setProtectedHeader({ alg })
    .setIssuedAt(new Date(vc.issuanceDate).getTime())
    .setExpirationTime(new Date(vc.expirationDate).getTime())
    .setIssuer(vc.issuer)
    .setSubject(vc.credentialSubject.id)
    .sign(key);
}
