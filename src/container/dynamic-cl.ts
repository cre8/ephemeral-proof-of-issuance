import { deflate, inflate } from 'pako';
import type { CredentialStatusSecretVcPayload } from '../dto/credential-status-secret-payload.js';
import type { DynamicCLVCPayload } from '../dto/dynamic-cl-vc-payload.js';
import { Container } from './container.js';
import { Entries } from '../dto/entries.js';

/**
 * A dynamic status list based on a CL.
 */
export class DynamicCL extends Container {
  entries = new Entries(new Set());

  async addValid(
    s_id: string,
    secret: string
  ): Promise<CredentialStatusSecretVcPayload> {
    const validHash = await this.calculateValidHash(secret, s_id);
    if (this.entries.has(validHash)) {
      throw new Error('Entry already exists');
    }
    this.entries.add(validHash);
    return this.createStatusVcPayload(secret, s_id);
  }

  /**
   * Remove the entry from the list
   * @param s_id
   * @param secret
   */
  async addInvalid(s_id: string, secret: string): Promise<void> {
    const validHash = await this.calculateValidHash(secret, s_id);
    this.entries.delete(validHash);
  }

  createVcPayload(): DynamicCLVCPayload {
    // create the vc
    const issuanceDate = new Date();
    const expirationDate = new Date();
    expirationDate.setSeconds(expirationDate.getSeconds() + this.epoch);
    return {
      jti: this.id,
      iss: this.issuer,
      // we need the lifetime for the vc-issuer, otherwhise the validator will not know that this list is no longer active
      iat: issuanceDate.getTime(),
      exp: expirationDate.getTime(),
      //we are compressing the entries, giving us around 10% compression
      entries: this.compressArrayBuffers(),
      hashFunction: this.hashFunction,
    };
  }

  /**
   * Compress an array of ArrayBuffers and return a Base64 string.
   * @param buffers Array of ArrayBuffers
   * @returns Compressed Base64 string
   */
  compressArrayBuffers(): string {
    // Store lengths of each buffer
    const array = this.entries.array();
    const lengths = new Uint32Array(array.length);
    //TODO: when all element has the same length, we can just calculate it
    const totalLength = array.reduce((sum, buf, index) => {
      lengths[index] = buf.byteLength;
      return sum + buf.byteLength;
    }, 0);

    // Merge all ArrayBuffers into a single Uint8Array
    const mergedArray = new Uint8Array(totalLength);
    let offset = 0;
    for (const buffer of array) {
      mergedArray.set(new Uint8Array(buffer), offset);
      offset += buffer.byteLength;
    }

    // Convert lengths to bytes and prepend them to the data
    const lengthsBuffer = new Uint8Array(lengths.buffer);
    const finalArray = new Uint8Array(
      lengthsBuffer.length + mergedArray.length
    );
    finalArray.set(lengthsBuffer, 0);
    finalArray.set(mergedArray, lengthsBuffer.length);

    // Compress using pako
    const compressed = deflate(finalArray);

    // Convert compressed data to Base64 string
    return btoa(String.fromCharCode(...compressed));
  }

  /**
   * Decompress a Base64 string back into an array of ArrayBuffers.
   * @param compressedString Base64 string
   * @returns Original array of ArrayBuffers
   */
  static decompressToArrayBuffers(compressedString: string): Set<ArrayBuffer> {
    // Convert Base64 string back to Uint8Array
    const binaryString = atob(compressedString);
    const compressedData = new Uint8Array(binaryString.length);

    for (let i = 0; i < binaryString.length; i++) {
      compressedData[i] = binaryString.charCodeAt(i);
    }

    // Decompress using pako
    const decompressed = inflate(compressedData);

    // Extract lengths (first part of the decompressed data)
    const numBuffers = decompressed.length / 32; // Assuming each buffer has a length entry
    const lengths = new Uint32Array(decompressed.buffer, 0, numBuffers);

    // Extract original ArrayBuffers
    let offset = lengths.byteLength;
    const result: Set<ArrayBuffer> = new Set();

    for (const length of lengths) {
      result.add(decompressed.slice(offset, offset + length).buffer);
      offset += length;
    }

    return result;
  }
}
