import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const patched = pathToFileURL(path.join(here, 'node_modules/o1js/dist/node/index.js')).href;

export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'o1js') return nextResolve(patched, context);
  return nextResolve(specifier, context);
}
