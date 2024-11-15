import { randomUUID } from 'crypto';
import {
  DEFAULT_EPOCH,
  DEFAULT_HMAC_FUNCTION,
  DEFAULT_HASH_FUNCTION,
} from '../const.js';
import { ContainerConfig } from '../dto/container-config.js';
import { CredentialStatusSecretVc } from '../dto/credential-status-secret.js';
import { HMACFunctionName, HashFunctionName, hash, hmac } from '../util.js';
import { JWTPayload } from 'jose';

/**
 * Base class for all containers that are used to store valid and invalid hashes.
 */
export abstract class Container {
  // id of the status list
  protected id: string;
  // issuer of the list
  protected issuer: string;

  // period in seconds a status list is valid
  protected epoch: number;

  // Count of the number of durations, where duration is chosen by use case, and t-now is a unix epoch value representing the current time.
  protected duration: number;
  // hash function used
  public hmacFunction!: HMACFunctionName;
  // hmac function used
  public hashFunction!: HashFunctionName;

  /**
   * Set the default values.
   * @param config
   */
  constructor(config: ContainerConfig) {
    this.id = config.id;
    this.issuer = config.issuer;
    this.epoch = config.epoch ?? DEFAULT_EPOCH;
    this.duration = Math.floor(Date.now() / 1000 / this.epoch);
    this.hmacFunction = config.hmacFunction ?? DEFAULT_HMAC_FUNCTION;
    this.hashFunction = config.hashFunction ?? DEFAULT_HASH_FUNCTION;
  }

  /**
   * Creates a vc that includes the token
   * @param secret The secret of the entry
   * @param s_id The id of the the vc
   * @returns payload of the vc
   */
  public createStatusVcPayload(
    secret: string,
    s_id: string
  ): CredentialStatusSecretVc {
    return {
      duration: this.duration,
      secret,
      sub: s_id,
      hmacFunction: this.hmacFunction,
      iat: new Date().getTime(),
      iss: this.issuer,
      jti: randomUUID().toString(),
    };
  }

  /**
   * Calculates the valid hash
   * @param secret The secret of the entry
   * @param s_id The id of the entry
   * @returns The valid hash
   */
  protected async calculateValidHash(
    secret: string,
    s_id: string
  ): Promise<string> {
    // time based password
    const token = await hmac(
      this.duration.toString(),
      secret,
      this.hmacFunction
    );
    // Status hash to declare validity
    return hash([token, s_id], this.hashFunction);
  }

  /**
   * Adds an entry to the list. Returns an unsigned vc that includes the token.
   * @param s_id The id of the entry
   * @param secret The secret of the entry
   */
  abstract addValid(
    s_id: string,
    secret: string
  ): Promise<CredentialStatusSecretVc>;

  /**
   * Adds the invalid hash to the list
   * @param s_id id of the vc
   * @param secret secret of the vc
   */
  abstract addInvalid(s_id: string, secret: string): Promise<void>;

  //TODO: maybe it should just be a promise to avoid wrong implementations
  /**
   * Creates an unsigned VC that includes the filter.
   */
  abstract createVcPayload(): JWTPayload | Promise<JWTPayload>;
}
