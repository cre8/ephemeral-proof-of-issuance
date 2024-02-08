import BloomFilter from 'bloom-filters';
import { deflate } from 'pako';
import { Worker } from 'worker_threads';
import {
  DynamicSLBloomFilterVC,
  ListPurpose,
} from './dto/dynamic-sl-bloom-filter.js';
import {
  hmac,
  hash,
  base64Encode,
  HMACFunctionName,
  HashFunctionName,
} from './util.js';
import { CredentialStatusSecretVc } from './dto/credential-status-secret.js';
import { randomUUID } from 'node:crypto';
import { DynamicSLBloomFilterConfig } from './dto/dynamic-sl-bloom-filter-config.js';
import {
  DEFAULT_EPOCH,
  DEFAULT_FALSE_POSITIVE,
  DEFAULT_HASH_FUNCTION,
  DEFAULT_HMAC_FUNCTION,
  DEFAULT_NBHASHES,
  DEFAULT_SIZE,
} from './const.js';
import { WorkerData } from './dto/worker-data.js';
import { VcStatus } from './dto/vc-status.js';

export class DynamicSLBloomFilter {
  // id of the status list
  id: string;
  // issuer of the list
  issuer: string;
  // path where the schema is located. Required for the vc-issuer to validate the vc
  dynamicSLBloomFilterSchema: string;
  // purpose of the list
  purpose: ListPurpose;
  // posibliity of a false positive event
  falsePositive: number;
  // size of the list
  size: number;
  // number of hash functions used
  nbHashes: number;
  // period in seconds a status list is valid
  epoch: number;

  // bloom filter used to store the values
  public bloomFilter: BloomFilter.BloomFilter;
  // Count of the number of durations, where duration is chosen by use case, and t-now is a unix epoch value representing the current time.
  private duration: number;
  // hash function used
  private hmacFunction!: HMACFunctionName;
  // hmac function used
  private hashFunctions!: HashFunctionName[];

  constructor(config: DynamicSLBloomFilterConfig) {
    this.id = config.id;
    this.issuer = config.issuer;
    this.dynamicSLBloomFilterSchema = config.dynamicSLBloomFilterSchema;
    this.purpose = config.purpose ?? 'revocation';
    this.falsePositive = config.falsePositive ?? DEFAULT_FALSE_POSITIVE;
    this.size = config.size ?? DEFAULT_SIZE;
    this.nbHashes = config.nbHashes ?? DEFAULT_NBHASHES;
    this.epoch = config.epoch ?? DEFAULT_EPOCH;
    this.duration = Math.floor(Date.now() / 1000 / this.epoch);
    this.hmacFunction = config.hmacFunction ?? DEFAULT_HMAC_FUNCTION;
    this.hashFunctions = [config.hashFunction] ?? [DEFAULT_HASH_FUNCTION];
    this.bloomFilter = BloomFilter.BloomFilter.create(
      this.size,
      this.falsePositive
    );
  }

  public static async addByWorker(
    config: DynamicSLBloomFilterConfig,
    entries: VcStatus[],
    worker = 10
  ) {
    const filter = new DynamicSLBloomFilter(config);
    // separate the entries into chunks defined by worker
    const chunkedEntries = DynamicSLBloomFilter.createChunks(entries, worker);
    try {
      const start = new Date();
      const workers = chunkedEntries.map((chunk) => filter.createWorker(chunk));
      const results = await Promise.all(workers);
      const hashCreated = new Date();
      results.forEach((hashes) => {
        hashes.forEach((hash) => filter.bloomFilter.add(hash));
      });
      const filterCreated = new Date();
      console.log({
        workerCount: worker,
        hashCreation: hashCreated.getTime() - start.getTime(),
        filterCreation: filterCreated.getTime() - hashCreated.getTime(),
      });
      return filter;
    } catch (error) {
      console.log(error);
      throw new Error('Error adding entries to the filter');
    }
  }

  /**
   * Creates chunks of the array by the number of chunks
   * @param array
   * @param chunkCounter
   * @returns array of chunks
   */
  private static createChunks(array: VcStatus[], chunkCounter: number) {
    const chunkSize = Math.max(Math.ceil(array.length / chunkCounter), 1);
    const chunks: VcStatus[][] = [];

    for (let i = 0; i < chunkCounter; i++) {
      const start = i * chunkSize;
      chunks.push(array.slice(start, start + chunkSize));
    }
    return chunks;
  }

  /**
   * Creates a worker that adds the hashes to the filter
   * @param workerData
   * @returns
   */
  private createWorker(elements: VcStatus[]): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const worker = new Worker('./dist/worker.js');

      worker.on('message', resolve);
      worker.on('error', reject);
      worker.on('exit', (code) => {
        if (code !== 0)
          reject(new Error(`Worker stopped with exit code ${code}`));
      });
      const data: WorkerData = {
        duration: this.duration.toString(),
        elements,
        hashFunction: this.hashFunctions[0],
        hmacFunction: this.hmacFunction,
      };
      worker.postMessage(data);
    });
  }

  /**
   * Adds an entry to the list. Returns an unsigned vc that includes the token
   * @param s_id
   * @param secret
   */
  async addValid(s_id: string, secret: string) {
    // time based password
    const token = await hmac(
      this.duration.toString(),
      secret,
      this.hmacFunction
    );
    // Status hash to declare validity
    const validHash = await hash([token, s_id], this.hashFunctions[0]);
    this.bloomFilter.add(validHash);
    return this.createStatusVc(secret, s_id);
  }

  /**
   * Creates a vc that includes the token
   * @param secret
   */
  private createStatusVc(
    secret: string,
    s_id: string
  ): CredentialStatusSecretVc {
    return {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'CredentialStatusSecret',
      ],
      credentialSubject: {
        duration: this.duration,
        secret,
        id: s_id,
        hmacFunction: this.hmacFunction,
      },
      credentialSchema: {
        type: 'FullJsonSchemaValidator2021',
        id: '',
      },
      issuanceDate: new Date().toISOString(),
      validFrom: new Date().toISOString(),
      issuer: this.issuer,
      id: randomUUID(),
    };
  }

  /**
   * Adds the invalid hash to the list
   * @param s_id
   * @param secret
   */
  async addInvalid(s_id: string, secret: string) {
    // time based password
    const token = await hmac(
      this.duration.toString(),
      secret,
      this.hmacFunction
    );
    // Status hash to declare validity
    const validHash = await hash([token, s_id], this.hashFunctions[0]);
    const invalidHash = await hash([validHash], this.hashFunctions[0]);
    this.bloomFilter.add(invalidHash);
  }

  /**
   * Creates an unsigned VC that includes the filter
   * @returns
   */
  createVc(): DynamicSLBloomFilterVC {
    // gzip and base64 encode the filter
    const filter = base64Encode(deflate(this.bloomFilter._filter.array));
    // create the vc
    const issuanceDate = new Date();
    const expirationDate = new Date();
    expirationDate.setSeconds(expirationDate.getSeconds() + this.epoch);
    return {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'DynamicSLBloomFilter',
      ],
      id: this.id,
      issuer: this.issuer,
      // we need the lifetime for the vc-issuer, otherwhise the validator will not know that this list is no longer active
      issuanceDate: issuanceDate.toISOString(),
      expirationDate: expirationDate.toISOString(),
      validFrom: issuanceDate.toISOString(),
      validUntil: expirationDate.toISOString(),
      credentialSubject: {
        // not clear why we need the fragment here. Can maybe be removed
        id: `${this.id}#list`,
        purpose: this.purpose,
        content: filter,
        hashFunction: this.hashFunctions,
      },
      credentialSchema: {
        id: this.dynamicSLBloomFilterSchema,
        type: 'FullJsonSchemaValidator2021',
      },
    };
  }
}
