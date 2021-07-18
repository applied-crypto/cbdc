const poseidon = require("../../lib/circomlib/src/poseidon.js");
const MerkleTree = require("./merkleTree");
const assert = require("assert");

const POSEIDON_MAX_LENGTH = 6;

/**
 * Hashes input with poseidon hash function. If string input, it converts it to byte array before
 * @param input {Array}
 * @returns {BigInt} Finite field hash
 */
function poseidonHash(input) {
    let inputArray = [];
    assert(input.length <= POSEIDON_MAX_LENGTH, "Max input length is 6")
    for (let i = 0; i < input.length; i++) {
        inputArray = inputArray.concat(convertInput(input[i]));
    }

    return poseidon(inputArray);

    function convertInput(input) {
        let inputArray;
        if (Number.isInteger(input) || typeof input === "bigint") {
            return input;
        } else if (typeof input === 'string') {
            if (input.length === 0) return "";
            if (/^\d+$/.test(input)) {
                if (input.length > 20) { return BigInt(input); } else { return Number(input); }
            }
            inputArray = [];
            // UTF 16 le
            for (let i = 0; i < input.length; i++) {
                const code = input.charCodeAt(i);
                inputArray.push(code & 255, code >> 8);
            }
            // Thus the max input length of poseidon is a bigint array of 8 the string hashing must be in a chained way
            let firstEl = inputArray[0];
            const POSEIDON_MAX_LENGTH = 6;
            for (let i = 1; i < inputArray.length / POSEIDON_MAX_LENGTH; i++) {
                let input = [firstEl]
                for (let j = 0; j < POSEIDON_MAX_LENGTH - 1; j++) {
                    if (typeof inputArray[i * POSEIDON_MAX_LENGTH + j] != 'undefined') {
                        input.push(inputArray[i * POSEIDON_MAX_LENGTH + j]);
                    }
                }
                firstEl = poseidon(input);
            }
            return firstEl
        } else {
            throw "No correct input type";
        }
    }
}

/**
 * Creates merkle tree instance with poseidon hasher
 * @param input {Array}
 * @param tree {<MerkleTree>}
 * @returns {MerkleTree}
 */
function poseidonMerkle(input, tree = undefined) {
    return new MerkleTree(input, poseidonHash, tree);
}

module.exports = {poseidonHash, poseidonMerkle};