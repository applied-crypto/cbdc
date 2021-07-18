*This repository is stated as work in progress*
# A Prototype for a Central Bank Digital currency with Support for Cash-Like Privacy
This prototype implements a subset of the features of the CBDC proposal by Matthias Babel, Alexander Bechtel, Jonas, 
Gross, Benjamin Schellinger, and Johannes Sedlmeir.

Yet, the prototype implements the Merkle-tree for storing the commitments, a list for the nullifiers, and the basics for 
account and transaction management. In addition, it supports fully private transactions while respecting 
account transaction limits, ensuring compliance by design.

## Roadmap
- SSI-based onboarding
- Semi-private transactions

## Install
- Install nodejs(@v16.0.0) and npm (@7.10.0)
- Go to cbdc 
- Install dependencies `npm install`
- Run an example transaction: ``node test.js``