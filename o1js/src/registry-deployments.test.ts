import { describe, expect, it } from 'vitest';
import { Experimental, PrivateKey } from 'o1js';
import { deploymentProblems, readDeployments } from './registry-deployments.js';

const empty = Experimental.BatchReducer.initialActionState.toString();
const record = (over: object = {}) => ({
  network: 'devnet', registry: PrivateKey.random().toPublicKey().toBase58(), slot: '100', actionState: empty, ...over,
});

describe('the registry deployment records', () => {
  it('are well-formed as checked in (none yet)', () => {
    expect(readDeployments()).toEqual([]);
  });

  it('accept one record per network', () => {
    expect(deploymentProblems({ deployments: [record(), record({ network: 'lightnet' })] })).toEqual([]);
  });

  it('refuse a malformed record, a second record for a network and a registry not seen empty', () => {
    expect(deploymentProblems({})).toEqual(['no "deployments" list']);
    expect(deploymentProblems({ deployments: [record({ network: '' })] })).toEqual(['deployment 0: no network']);
    expect(deploymentProblems({ deployments: [record(), record()] })).toEqual(['deployment 1: a second record for devnet']);
    expect(deploymentProblems({ deployments: [record({ registry: 'nope' })] })).toEqual(['deployment 0: the registry is not an address']);
    expect(deploymentProblems({ deployments: [record({ slot: 'x' })] })).toEqual(['deployment 0: the slot is not a number']);
    expect(deploymentProblems({ deployments: [record({ actionState: '5' })] })).toHaveLength(1);
  });
});
