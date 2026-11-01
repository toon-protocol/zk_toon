// `fixture-gen/land.mjs`, the toy program zk-prover proves, with this package's o1js. Written as that
// file is: a version with `declareState` and field initialisers compiled two rows longer, to another key. The
// pinned verification key hash (`land-program.test.ts`) says the two are the same circuit.
import { PublicKey, Signature, SmartContract, State, UInt64, declareMethods, state } from 'o1js';

export class Land extends SmartContract {
  declare landed: State<UInt64>;
  declare payer: State<PublicKey>;

  constructor(address: PublicKey) {
    super(address);
    this.landed = State();
    this.payer = State();
  }

  async init() {
    super.init();
  }

  async setup(payer: PublicKey) {
    this.payer.set(payer);
  }

  async land(cumulative: UInt64, sig: Signature) {
    const payer = this.payer.getAndRequireEquals();
    const landed = this.landed.getAndRequireEquals();
    sig.verify(payer, cumulative.toFields()).assertTrue();
    cumulative.assertGreaterThan(landed);
    this.landed.set(cumulative);
  }
}

state(UInt64)(Land.prototype, 'landed');
state(PublicKey)(Land.prototype, 'payer');
// `land` comes first: the order of the methods is part of the program's key.
declareMethods(Land, { land: [UInt64, Signature], setup: [PublicKey] } as Record<string, any[]>);

/** The hash in `zk-prover/src/pins.rs`, `PROGRAM_VK_HASH`. */
export const PROGRAM_VK_HASH = '9870947700175903446193934776973478446598173288641875524808838875088037769766';
