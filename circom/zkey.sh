#!/bin/bash

HOME_DIR=$(pwd)
cd $1

# Building circuit
circom circuit.circom --r1cs --wasm --sym 
# Infos about the circuit
snarkjs info -c circuit.r1cs
# Start a new zkey and make a contribution
snarkjs zkey new circuit.r1cs $HOME_DIR/powersOfTau28_hez_final_16.ptau circuit_0000.zkey -v 
snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey --name="1st Contributor Name" -e="random" -v 
# Export the verification key
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json

