*This repository is stated as work in progress*
# A Prototype for a Central Bank Digital currency with Support for Cash-Like Privacy
This prototype implements a subset of the features of the CBDC proposal by [Matthias Babel](https://www.linkedin.com/in/matthiasbabel/), [Alexander Bechtel](https://www.linkedin.com/in/alexanderbechtel/), [Jonas Gross](https://www.linkedin.com/in/jonasgross94/), [Benjamin Schellinger](https://www.linkedin.com/in/benjamin-schellinger-a35684125/), and [Johannes Sedlmeir](https://www.linkedin.com/in/johannes-sedlmeir/).

Yet, the prototype implements the Merkle-tree for storing the commitments, a list for the nullifiers, and the basics for 
account and transaction management. In addition, it supports fully private transactions while respecting 
account transaction limits, ensuring compliance by design.

This is achieved by implementing generic zero-knowledge proofs (SNARKs) using the iden3 libraries [circom](https://github.com/iden3/circom) and [snarkjs](https://github.com/iden3/snarkjs)

## Roadmap
- SSI-based onboarding
- Semi-private transactions

## Install
- Install nodejs(@v16.0.0) and npm (@7.10.0)
- Go to cbdc 
- Install dependencies `npm install`
- Run an example transaction: ``node test.js``

