// A toy that exercises recursion, kept apart from the vault: a ZkProgram with one method, and a zkApp
// with two methods, `plain` verifying no proof and `recurse` verifying a proof of the ZkProgram.
import { SmartContract, ZkProgram, Field, method, declareMethods } from 'o1js';

export const Inner = ZkProgram({
  name: 'toy-inner',
  publicInput: Field,
  methods: {
    base: {
      privateInputs: [Field],
      async method(x, y) {
        x.assertEquals(y.mul(y));
      },
    },
  },
});
export class InnerProof extends ZkProgram.Proof(Inner) {}

export class Outer extends SmartContract {
  constructor(a) { super(a); }
  async plain(x) { x.assertEquals(x); }
  async recurse(x, proof) {
    proof.verify();
    proof.publicInput.assertEquals(x);
  }
}
declareMethods(Outer, { plain: [Field], recurse: [Field, InnerProof] });
