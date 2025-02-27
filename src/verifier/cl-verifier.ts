import { DynamicList } from '../container/dynamic-list.js';
import type { CredentialStatusTokenPayload } from '../dto/credential-status-token-payload.js';
import type { DynamicListVCPayload } from '../dto/dynamic-list-vc-payload.js';
import { Entries } from '../dto/entries.js';
import type { VerifierConfig } from '../dto/verifier-config.js';
import { hash } from '../util.js';
import { Verifier } from './verifier.js';

/**
 * Verifier that can be used to verify the crl
 */
export class ClVerifier extends Verifier {
  private entries: Entries;

  /**
   * Iinit the verifier
   * @param config
   */
  constructor(config: VerifierConfig<DynamicListVCPayload>) {
    super(config);
    // create an object for the list, rather than managing the entries here.
    this.entries = new Entries(
      DynamicList.decompressToArrayBuffers(config.vc.entries),
    );
  }

  /**
   * Checks if the valid value is included and the invalid is not included
   * @param vc
   * @returns
   */
  async isValid(vc: CredentialStatusTokenPayload) {
    if (this.timeCheck && this.validUntil < Date.now())
      throw new Error('CRL is no longer valid');
    // TODO validate the signature of the vc
    const validHash = await hash([vc.token, vc.sub], this.hashFunction);
    return this.entries.has(validHash);
  }
}
