*This repository is stated as work in progress*
# A Prototype for a Central Bank Digital Currency with Support for Cash-Like Privacy
This prototype implements a subset of the features of the CBDC proposal by Matthias Babel, Alexander Bechtel, Jonas Gross, Benjamin Schellinger, and Johannes Sedlmeir.

So far, the prototype implements the Merkle-tree for storing the commitments, a list for the nullifiers, and the basics for 
account and transaction management. In addition, it supports semi-private deposits and fully private transactions while respecting 
account transaction limits, ensuring compliance by design.

This is achieved by implementing generic zero-knowledge proofs (SNARKs) using the iden3 libraries [circom](https://github.com/iden3/circom) and [snarkjs](https://github.com/iden3/snarkjs)

## Roadmap
- Digital ID-based private onboarding
- Semi-private transactions
- Implement a sparse Merkle tree for the nullifiers
- Performance tests for realistic Merkle tree depth

## Install
- Install nodejs(@v16.0.0) and npm (@7.10.0)
- Go to cbdc 
- Install dependencies `npm install`
- Run an example transaction: ``node test.js``

