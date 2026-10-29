// Connects o1js to the proofs-on lightnet started by `lightnet/lightnet.sh up`, and lends a funded
// genesis account from its account manager. Shared by the lightnet tests (`*.lightnet.ts`).
import { Lightnet, Mina } from 'o1js';

const MINA = 'http://127.0.0.1:8080/graphql';
const ARCHIVE = 'http://127.0.0.1:8282';
const ACCOUNT_MANAGER = 'http://127.0.0.1:8181';

/** Sets the lightnet as the active chain and acquires a funded sender; `release` gives it back. */
export async function connectLightnet() {
  Mina.setActiveInstance(
    Mina.Network({ networkId: 'testnet', mina: MINA, archive: ARCHIVE, lightnetAccountManager: ACCOUNT_MANAGER })
  );
  const { publicKey, privateKey } = await Lightnet.acquireKeyPair();
  return {
    sender: Mina.TestPublicKey(privateKey),
    release: () => Lightnet.releaseKeyPair({ publicKey: publicKey.toBase58() }),
  };
}
