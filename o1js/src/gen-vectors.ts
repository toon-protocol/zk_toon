import { writeFileSync } from 'node:fs';
import { buildVectors } from './vectors.js';

const path = new URL('../../test-vectors/zk-note.json', import.meta.url);
writeFileSync(path, JSON.stringify(buildVectors(), null, 2) + '\n');
console.log(`wrote ${path.pathname}`);
