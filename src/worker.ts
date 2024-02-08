import { parentPort } from 'worker_threads';
import { hash, hmac } from './util.js';
import { WorkerData } from './dto/worker-data.js';

if (parentPort) {
  parentPort.on('message', (data: WorkerData) => {
    Promise.all(
      data.elements.map(async (element) => {
        // time based password
        const token = await hmac(
          data.duration,
          element.secret,
          data.hmacFunction
        );
        // Status hash to declare validity
        const validHash = await hash([token, element.s_id], data.hashFunction);
        if (element.valid) return validHash;
        return hash([validHash], data.hashFunction);
      })
    ).then((hashes) => parentPort!.postMessage(hashes));
  });
}
