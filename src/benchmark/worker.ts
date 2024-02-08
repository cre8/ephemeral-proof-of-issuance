import { randomUUID } from 'crypto';
import {
  DEFAULT_EPOCH,
  DEFAULT_FALSE_POSITIVE,
  DEFAULT_NBHASHES,
} from '../src/const.js';
import { DynamicSLBloomFilterConfig } from '../src/dto/dynamic-sl-bloom-filter-config.js';
import { VcStatus } from '../src/dto/vc-status.js';
import { DynamicSLBloomFilter } from '../src/dynamic-sl-bloom-filter.js';
import { createSecret } from '../src/util.js';

// path where the schema is located. Required for the vc-issuer to validate the vc
const dynamicSLBloomFilterSchema = 'pathToTheSchema';
// issuer reference of the vc statuslist
const issuer = 'did:web:exmaple.com';

async function runWorkerScale() {
  const config: DynamicSLBloomFilterConfig = {
    dynamicSLBloomFilterSchema,
    id: randomUUID(),
    issuer,
    epoch: DEFAULT_EPOCH,
    falsePositive: DEFAULT_FALSE_POSITIVE,
    nbHashes: DEFAULT_NBHASHES,
    purpose: 'revocation',
    size: 100000,
    hashFunction: 'SHA-256',
    hmacFunction: 'SHA-256',
  };
  const entries: VcStatus[] = [];
  for (let i = 0; i < config.size!; i++) {
    entries.push({
      s_id: randomUUID(),
      secret: createSecret(),
      valid: false,
    });
  }
  for (let workCounter = 1; workCounter < 10; workCounter++) {
    await DynamicSLBloomFilter.addByWorker(config, entries, workCounter);
  }
}
runWorkerScale();
