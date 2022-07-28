const path = require("path");
const fs = require("fs");
const {performance} = require('perf_hooks');
const snarkjs = require('snarkjs');


class Update {
    publicSignals
    proof

    /**
     * Generates public signals and proof from private input
     * @param input
     * @returns {Promise<boolean>}
     */
    async generateProof(input) {
        let root = process.mainModule.paths[0].split('node_modules')[0].slice(0, -1);
        let t0 = performance.now();
        console.log(input)
        const {proof, publicSignals} = await snarkjs.groth16.fullProve(
            input,
            path.join(root, "zkp", "update", "circuit.wasm"),
            path.join(root, "zkp", "update", "circuit_final.zkey")
        ).catch(console.log);
        let t1 = performance.now();
        console.log("Prove took " + (t1 - t0) + " milliseconds.");

        this.publicSignals = publicSignals;
        this.proof = proof;
        let res = await this.verifyProof();

        if (res === true) {
            return Promise.resolve(true);
        } else {
            this.publicSignals = undefined;
            this.proof = undefined;
            return Promise.reject(false);
        }
    }

    get receiver() {
        if(this.publicSignals[5] === "1")
            return true;
        if(this.publicSignals[5] === "0")
            return false;
        else
            throw "Invalid";
    }

    get privacyPoolRoot() {
       return this.publicSignals[0];
    }

    get linkTransfer() {
        return this.publicSignals[1];
    }

    get timestamp() {
        return this.publicSignals[6];
    }

    get linkNationality() {
        return this.publicSignals[2];
    }

    get nullifier() {
        return this.publicSignals[3];
    }

    get nextCommitment() {
        return this.publicSignals[4];
    }

    /**
     * Verifies if public signals and proof correspond
     * @returns {Promise<boolean>}
     */
    async verifyProof() {
        let root = process.mainModule.paths[0].split('node_modules')[0].slice(0, -1);
        const vKey = JSON.parse(fs.readFileSync(path.join(root, "zkp", "update", "verification_key.json")));

        let res = await snarkjs.groth16.verify(vKey, this.publicSignals, this.proof).catch(err => console.error(err));
        if (res === true) {
            return Promise.resolve(true);
        } else {
            return Promise.reject(false);
        }

    }
}

module.exports = Update;