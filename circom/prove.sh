#!/bin/bash

HOME_DIR=$(pwd)
cd $1
# Calculate witness
(
 cd circuit_js
 node generate_witness.js circuit.wasm ../input_private.json ../witness.wtns
)
#snarkjs wtns calculate circuit.wasm input_private.json witness.wtns
#snarkjs wtns debug circuit.wasm input_private.json witness.wtns circuit.sym --trigger --get --set 2>&1 | tee log.txt
# Generate zk-proof
snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json input_public.json
# Verify the proof
snarkjs groth16 verify verification_key.json input_public.json proof.json
