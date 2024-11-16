import { JWTPayload } from 'jose';
import { ContainerConfig } from '../dto/container-config.js';
import { CredentialStatusSecretVcPayload } from '../dto/credential-status-secret-payload.js';
import { Container } from './container.js';
import { hash } from '../util.js';
import { DynamicCRLVCPayload } from '../dto/dynamic-crl-vc-payload.js';

/**
 * A dynamic status list based on a CRL.
 */
export class DynamicCRL extends Container {
  entries = new Set<string>();

  constructor(config: ContainerConfig) {
    super(config);
  }

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

  async addInvalid(s_id: string, secret: string): Promise<void> {
    const validHash = await this.calculateValidHash(secret, s_id);
    const invalidHash = await hash([validHash], this.hashFunction);
    this.entries.add(invalidHash);
  }

  createVcPayload(): DynamicCRLVCPayload {
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
      entries: Array.from(this.entries),
      hashFunction: this.hashFunction,
    };
  }
}
