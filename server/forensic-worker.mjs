import { parentPort, workerData } from 'node:worker_threads';
import { parseArtifact, FORENSIC_LIMITS } from './forensic-parsers.mjs';
try {
  const result = parseArtifact(workerData.bytes, workerData.options, workerData.context);
  if (Buffer.byteLength(JSON.stringify(result)) > FORENSIC_LIMITS.outputBytes)
    throw new Error('Parser output size limit exceeded');
  parentPort.postMessage({ ok: true, result });
} catch (error) {
  parentPort.postMessage({ ok: false, error: error.message.slice(0, 300) });
}
