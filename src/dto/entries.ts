/**
 * Entries class to manage array of ArrayBuffers
 */
export class Entries {
  constructor(private entries: Set<ArrayBuffer>) {}

  /**
   * Get the array of entries
   * @returns
   */
  array() {
    return Array.from(this.entries);
  }

  /**
   * Delete an array from the set
   * @param validHash
   */
  delete(validHash: ArrayBuffer) {
    this.entries.delete(validHash);
  }

  /**
   * Add an array to the set
   * @param validHash
   */
  add(validHash: ArrayBuffer) {
    this.entries.add(validHash);
  }

  /**
   * Check if the array is in the set
   * @param array
   * @returns
   */
  has(array: ArrayBuffer) {
    return Array.from(this.entries).some((entry) =>
      this.arrayBuffersEqual(entry, array),
    );
  }

  private arrayBuffersEqual(buf1: ArrayBuffer, buf2: ArrayBuffer): boolean {
    if (buf1.byteLength !== buf2.byteLength) {
      return false; // Different sizes, cannot be equal
    }

    const view1 = new Uint8Array(buf1);
    const view2 = new Uint8Array(buf2);
    for (let i = 0; i < view1.length; i++) {
      if (view1[i] !== view2[i]) {
        return false; // Found a difference
      }
    }

    return true; // All bytes match
  }
}
