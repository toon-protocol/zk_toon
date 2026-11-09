// Makes every `import 'o1js'` in the vault's sources (../o1js/src) resolve to this package's patched o1js,
// the one that dumps circuits and witnesses when SPIKE_DUMP is set. Used as `--import ./vault-register.mjs`.
import { register } from 'node:module';
register('./vault-resolve.mjs', import.meta.url);
