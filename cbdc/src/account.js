const {signPoseidon} = require("../lib/circomlib/src/eddsa");
const {poseidonHash} = require("./crypto/poseidon");
const {poseidonMerkle} = require("./crypto/poseidon");
const {EdDSAKey} = require("./crypto/key");
const Update = require("./update");
const {getTimestamp} = require("./util");
const {stringifyBigInts} = require("./util");
const {AttributePresentation, merklePoseidon} = require("../../heimdall/heimdalljs");

//for debugging
const {wasm} = require("circom_tester");
const path = require("path");

const EPOCH_TURNOVER_INTERVAL = 2592000; // 30 * 24 * 60 * 60
const EPOCH_TURNOVER = 150;


class Account {
    stack
    sk
    nationality
    counter
    id

    /**
     * Manages a account
     * @param balance {Number}
     * @param nationality {String}
     */
    constructor(balance, nationality, sessionNumber) {
        this.sk = EdDSAKey.newKey();
        this.nationality = nationality;
        this.stack = [
            {
                balance: balance,
                epochTurnover: 0,
                lastReset: getTimestamp(),
                sessionNumber: sessionNumber
            }
        ];
        this.counter = 0;
    }

    /**
     * Current balance
     * @returns {Number}
     */
    get balance() {
        return this.stack[this.counter].balance;
    }

    /**
     * Current epoch turnover
     * @returns {Number}
     */
    get epochTurnover() {
        return this.stack[this.counter].epochTurnover;
    }

    /**
     * Current last reset
     * @returns {Number}
     */
    get lastReset() {
        return this.stack[this.counter].lastReset;
    }

    /**
     * Returns public key
     * @returns {[BigInt]}
     */
    get publicKey() {
        return EdDSAKey.getPublicKey(this.sk);
    }

    /**
     * Current commitment
     * @returns {BigInt}
     */
    get commitment() {
        return this.getCommitment(this.counter);
    }

    /**
     * Current nullifier
     * @returns {BigInt}
     */
    get nullifier() {
        return this.getNullifier(this.counter);
    }

    /**
     * Returns commitment of index
     * @param index {Number}
     * @returns {BigInt}
     */
    getCommitment(index) {
        let commitment = poseidonHash(this.getCommitmentSignature(index));
        return commitment;
    }

    /**
     * Returns unhashed signature of commitment
     * @param index
     * @returns {[BigInt]}
     */
    getCommitmentSignature(index) {
        let element = this.stack[index];
        let tree = poseidonMerkle([
            this.nationality, // Nationality
            this.counter, // Counter
            element.balance, // Balance
            element.epochTurnover, // Epoch turnover
            element.lastReset, // Last reset
            element.sessionNumber,
            "",
            ""
        ]);
        let signature = signPoseidon(this.sk, tree.root);
        return [signature.R8[0], signature.R8[1], signature.S];
    }

    /**
     * Returns nullifier of index
     * @param index {Number}
     * @returns {BigInt}
     */
    getNullifier(index) {
        let nullifierSignature = signPoseidon(this.sk, poseidonHash([index]));
        let nullifier = [nullifierSignature.R8[0], nullifierSignature.R8[1], nullifierSignature.S];
        return nullifier;
    }

    /**
     * Returns stack of index
     * @param index {Number}
     * @returns {Object}
     */
    getStack(index) {
        return this.stack[index];
    }

    /**
     * Updates stack with given amount
     * @param amount {Number}
     * @param privacyPool {PrivacyPool}
     * @param sessionNumber {Number}
     * @param revocationRegistry {RevocationRegistry}
     * @returns update {Update}
     */
    async update(amount, privacyPool, sessionNumber, revocationRegistry) {
        if (typeof this.id === 'undefined') return Promise.reject("No ID given");
        if (amount > this.balance) return Promise.reject("Balance to low"); // only if the account is the sender; in this case, is amount negative? Or do we add a sender/receiver tag?
        let element = this.stack[this.counter];
        let timestamp = getTimestamp();
        let newLastReset;
        let newEpoch;
        if (timestamp - element.lastReset > EPOCH_TURNOVER_INTERVAL) {
            newLastReset = timestamp;
            newEpoch = Math.abs(amount);
        } else {
            newLastReset = element.lastReset;
            newEpoch = element.epochTurnover + Math.abs(amount);
        }
        if (newEpoch > EPOCH_TURNOVER) return Promise.reject("Not in this epoch");
        this.stack.push(
            {
                balance: element.balance + amount,
                epochTurnover: newEpoch,
                lastReset: newLastReset,
                sessionNumber: sessionNumber
            }
        );
        let emptyHash = poseidonHash([""]);
        let privateInput = {};
        privateInput.previousCommitmentInput = [
            poseidonHash([this.nationality]),
            this.counter,
            element.balance,
            element.epochTurnover,
            element.lastReset,
            element.sessionNumber,
            emptyHash,
            emptyHash
        ];
        let proof = privacyPool.getProof(this.commitment);
        privateInput.lemmaPreviousCommitment = proof.lemma;
        privateInput.pathPreviousCommitment = proof.path;
        if (amount > 0) {
            privateInput.receiver = 1;
        } else {
            privateInput.receiver = 0;
        }
        privateInput.previousCommitmentSignature = this.getCommitmentSignature(this.counter);
        privateInput.sessionNumber = sessionNumber;
        privateInput.amount = Math.abs(amount);
        privateInput.publicKey = this.publicKey;
        let nullifierSignature = signPoseidon(this.sk, poseidonHash([this.counter]));
        privateInput.nullifierSignature = [nullifierSignature.R8[0], nullifierSignature.R8[1], nullifierSignature.S];

        privateInput.timestamp = getTimestamp();

        this.counter++;
        let elementNew = this.stack[this.counter];
        privateInput.nextCommitmentSessionNumber = elementNew.sessionNumber;
        privateInput.nextCommitmentSignature = this.getCommitmentSignature(this.counter);
        let idPresentation = new AttributePresentation(
            this.id,
            privateInput.timestamp,
            revocationRegistry,
            privateInput.sessionNumber,
            this.sk,
            this.id.signature.pk,
            signPoseidon,
            merklePoseidon,
            Number(2)
        );

        let finalPrivateInput = Object.assign({}, privateInput, idPresentation.privateInput);
        delete finalPrivateInput.expiration;
        delete finalPrivateInput.challenge;
        //console.log(JSON.stringify(stringifyBigInts(finalPrivateInput)));

        //for debugging
        //const cir = await wasm(path.join(__dirname, "..", "..", "circom", "circuit", "circuit.circom"));
        //let witness = await cir.calculateWitness(finalPrivateInput, true);
        //let witness = await cir.calculateWitness(privateInput, true);
        //console.debug(witness.slice(0, 22));

        let update = new Update();
        await update.generateProof(finalPrivateInput);

        return Promise.resolve(update);
    }
}

module.exports = Account;