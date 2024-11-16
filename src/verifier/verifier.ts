import { JWTPayload } from 'jose';
import { HashFunctionName } from '../util.js';
import { VerifierConfig } from '../dto/verifier-config.js';
import { ContainerVCPayload } from '../dto/container-vc-payload.js';

export abstract class Verifier {
  // time when the bloom filter is no longer valid
  protected validUntil: number;
  protected timeCheck: boolean;
  protected hashFunction: HashFunctionName;

  constructor(config: VerifierConfig<ContainerVCPayload>) {
    this.timeCheck = config.timeCheck ?? false;
    // we are looking on the validUntil field of the status list credential, not the one we get from the holder.
    this.validUntil = new Date(config.vc.exp as number).getTime();

    this.hashFunction = config.vc.hashFunction;
  }

  abstract isValid(vc: JWTPayload): Promise<boolean>;
}
