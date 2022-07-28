#!/bin/bash
HOME_DIR=$(pwd)
PTAU=$HOME_DIR/powersOfTau28_hez_final_16.ptau
# https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_17.ptau

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then

    echo "Usage: zkey <type> <protocol> <dir> <rapid>"

    exit

fi

cd $3

if [ ! -f circuit.circom ]; then

    echo "No circuit.circom file found"

    exit

fi

if [ ! -d dist ]; then
    mkdir dist
    (
      cd dist
      npm init -y
    )
fi

if [ "$2" = "plonk" ]; then

    if [ "$1" = "zkey" ]; then

        circom circuit.circom --r1cs --wasm --sym -o dist

        cd dist/circuit_js

        node generate_witness.js circuit.wasm ../../input.json ../witness.wtns

        cd ../..

        snarkjs plonk setup dist/circuit.r1cs $PTAU dist/circuit_final.zkey

        snarkjs zkey export verificationkey dist/circuit_final.zkey dist/verification_key.json

        snarkjs r1cs info dist/circuit.r1cs

    elif [ "$1" = "prove" ]; then

        cd dist/circuit_js

        START="$(date +%s%N)"

        node generate_witness.js circuit.wasm ../../input.json ../witness.wtns

        END="$(date +%s%N)"

        echo "Witness generation time: $((END - START))"

        cd ../..

        START="$(date +%s%N)"

        snarkjs plonk prove dist/circuit_final.zkey dist/witness.wtns proof.json public.json

        END="$(date +%s%N)"

        echo "Proving time: $((END - START))"

        START="$(date +%s%N)"

        snarkjs plonk verify dist/verification_key.json public.json proof.json

        END="$(date +%s%N)"

        echo "Proving time: $((END - START))"

    else

        echo "Valid types are: zkey, prove"

        exit

    fi

elif [ "$2" = "groth16" ]; then

    if [ "$1" = "zkey" ]; then

        circom circuit.circom --r1cs --wasm --sym -o dist
(
        cd dist/circuit_js

        node generate_witness.js circuit.wasm ../../input.json ../witness.wtns
)
        snarkjs groth16 setup dist/circuit.r1cs $PTAU dist/circuit_final.zkey
        # No further contribution or random beacon applied
        snarkjs zkey verify dist/circuit.r1cs $PTAU dist/circuit_final.zkey

        snarkjs zkey export verificationkey dist/circuit_final.zkey dist/verification_key.json

        snarkjs r1cs info dist/circuit.r1cs

    elif [ "$1" = "prove" ]; then

        cd dist/circuit_js

        START="$(date +%s%N)"

        node generate_witness.js circuit.wasm ../../input.json ../witness.wtns

        END="$(date +%s%N)"

        echo "Witness generation time: $((END - START))"

        cd ../..

        START="$(date +%s%N)"

        if [ "$4" = "rapid" ]; then

            $HOME_DIR/rapidsnark/build/prover dist/circuit_final.zkey dist/witness.wtns proof.json public.json

        else

            snarkjs groth16 prove dist/circuit_final.zkey dist/witness.wtns proof.json public.json

        fi

        END="$(date +%s%N)"

        echo "Proving time: $((END - START))"

        START="$(date +%s%N)"

        snarkjs groth16 verify dist/verification_key.json public.json proof.json

        END="$(date +%s%N)"

        echo "Proving time: $((END - START))"

    else

        echo "Valid types are: zkey, prove"

        exit

    fi

else

    echo "only plonk or groth16 available"

fi
