import { randomUUID } from 'crypto';
import { DynamicCL } from '../src/container/dynamic-cl.js';
import { ContainerConfig } from '../src/dto/container-config.js';
import { createSecret } from '../src/util.js';

// issuer reference of the vc statuslist
const issuer = 'http://example.com';

const config: ContainerConfig = {
  id: randomUUID(),
  issuer,
};
const statuslist = new DynamicCL(config);
const length = 100000;
for (let i = 0; i < length; i++) {
  const id = randomUUID();
  const secret = createSecret();
  await statuslist.addValid(id, secret);
}
const dynamicCRLVC = statuslist.createVcPayload();
