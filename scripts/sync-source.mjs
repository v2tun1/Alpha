import { copyFile } from 'node:fs/promises';

await copyFile(new URL('../src/worker.js', import.meta.url), new URL('../public/downloads/worker-source.js', import.meta.url));
console.log('Synced src/worker.js to public/downloads/worker-source.js');
