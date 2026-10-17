import { copyFile, mkdir } from 'node:fs/promises';

await mkdir('public', { recursive: true });
for (const file of ['alpha-core.js', 'alpha-scan.dat']) {
  await copyFile(file, `public/${file}`);
}
console.log('Worker source assets synchronized.');
