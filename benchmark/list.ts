import { randomUUID } from 'crypto';
import { DynamicList } from '../src/container/dynamic-list.js';
import { ContainerConfig } from '../src/dto/container-config.js';
import { createSecret } from '../src/util.js';
import { writeFileSync, existsSync, readFileSync } from 'fs';
import { resolve } from 'path';

// issuer reference of the vc statuslist
const issuer = 'http://example.com';

const maxamount = 100000;
interface Entry {
  id: string;
  secret: string;
}

/**
 * Function to generates values at the beginning. In most cases we are intersted how fast a refresh is, so these values already exist
 */
function getSecrets(length: number) {
  const file = 'benchmark/entries.json';
  if (existsSync(file)) {
    return (JSON.parse(readFileSync(file, 'utf-8')) as Entry[]).slice(
      0,
      length
    );
  }
  const elements: { id: string; secret: string }[] = [];
  for (let i = 0; i < maxamount; i++) {
    elements.push({
      id: randomUUID(),
      secret: createSecret(),
    });
  }
  writeFileSync('test.json', JSON.stringify(elements));
  return elements.slice(0, length);
}

const config: ContainerConfig = {
  id: randomUUID(),
  issuer,
};

async function calculate(length: number) {
  const start = new Date().getTime();
  const statuslist = new DynamicList(config);
  const entries = getSecrets(length);

  for (let i = 0; i < entries.length; i++) {
    await statuslist.addValid(entries[i].id, entries[i].secret, false);
  }
  const timeAfterAdding = new Date().getTime();
  const addedTime = timeAfterAdding - start;
  const dynamicCRLVC = statuslist.createVcPayload();
  const size = Math.floor(JSON.stringify(dynamicCRLVC).length / 1024);
  const totalTime = new Date().getTime() - start;
  const compressionTime = new Date().getTime() - timeAfterAdding;
  const estimatedSize = Math.round((length * 32) / 1000);
  return {
    size,
    estimatedSize,
    time: totalTime,
    compressionTime,
    addedTime,
    length,
  };
}
const results = [];
const steps = 10000;
for (let amount = 10000; amount <= maxamount; amount = amount + steps) {
  const result = await calculate(amount);
  console.log(result);
  results.push(result);
}
writeFileSync('benchmark/results.json', JSON.stringify(results));
