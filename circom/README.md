# Circuit

## Install snarkjs and circom
```npm install -g circom snarkjs```

## Build circuit and generate zkey

- Download [powers of tau](https://www.dropbox.com/sh/mn47gnepqu88mzl/AAAI-XPJ7jKfw6FfZzqhiFspa/powersOfTau28_hez_final_16.ptau?dl=0) and store it in the root of the circom folder
- Run ```sh zkey.sh <Path to dir of circuit> ```

## Generate proof

- Insert public input in input_public.json in the folder of the circuit
- Run ```sh prove.sh <Path to dir of circuit>```

## Copy circuit data to js 
- Run ```sh copy.sh <Path to dir of circuit> <Folder name in js zkp folder>``` 
- Example: ```sh copy.sh circuit update```