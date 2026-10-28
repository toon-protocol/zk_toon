// A deliberately tiny "land a voucher" zkApp.
import { SmartContract, state, State, method, UInt64, PublicKey, Signature, Bool, declareMethods } from 'o1js';

export class Land extends SmartContract {
  constructor(a) { super(a); this.landed = State(); this.payer = State(); }
  async init() { super.init(); }
  async setup(payer) { this.payer.set(payer); }
  async land(cumulative, sig) {
    const payer = this.payer.getAndRequireEquals();
    const landed = this.landed.getAndRequireEquals();
    sig.verify(payer, cumulative.toFields()).assertTrue();
    cumulative.assertGreaterThan(landed);
    this.landed.set(cumulative);
  }
}
state(UInt64)(Land.prototype, 'landed');
state(PublicKey)(Land.prototype, 'payer');
declareMethods(Land, { land: [UInt64, Signature], setup: [PublicKey] });
