const {getTimestamp} = require("./util");
const {poseidonMerkle} = require("./crypto/poseidon");
const SIZE = 5;

class PrivacyPool {
    commitmentsTree
    nullifiers
    counter

    constructor() {
        this.nullifiers = [];
        let array = Array(32).fill(0);
        this.commitmentsTree = poseidonMerkle(array);
        this.counter = -1;
    }

    /**
     * First onboarding of a account
     * @param commitment {BigInt}
     */
    onboard(commitment) {
        this.commitmentsTree.update(++this.counter, commitment);
    }

    /**
     * Returns root of the commitments tree
     * @returns {BigInt}
     */
    get root() {
        return this.commitmentsTree.root;
    }

    /**
     * Returns nullifier array
     * @returns {[BigInt]}
     */
    get commitments() {
        return this.commitmentsTree.leaves;
    }

    /**
     * Returns proof for the commitment given
     * @param index
     * @returns {Proof}
     */
    getProof(element) {
        let index = this.commitmentsTree.leaves.indexOf(element);
        if (index === -1) throw "Commitment does not exists";
        return this.commitmentsTree.generateProof(index);
    }

    /**
     * Checks if nullifier exists in the list
     * @param nullifier {BigInt}
     * @returns {boolean}
     */
    nullifierExists(nullifier) {
        return this.nullifiers.includes(nullifier);
    }

    /**
     *
     * @param sender {Update}
     * @param receiver {Update}
     */
    async update(sender, receiver) {
        let validity = await sender.verifyProof();
        validity &= await receiver.verifyProof();
        validity &= !this.nullifierExists(sender.nullifier);
        validity &= !this.nullifierExists(receiver.nullifier);
        if(!validity) return Promise.reject("Proofs invalid");
        if(sender.receiver === receiver.receiver) return Promise.reject("Incorrect sender receiver relation");
        if(sender.linkTransfer !== receiver.linkTransfer) return Promise.reject("Transfer links not the same");
        if(receiver.timestamp < getTimestamp() - 360 && sender.timestamp < getTimestamp() - 360)
            return Promise.reject("Transfers too old");
        this.commitmentsTree.update(++this.counter, BigInt(sender.nextCommitment));
        this.commitmentsTree.update(++this.counter, BigInt(receiver.nextCommitment));
        this.nullifiers.push(BigInt(sender.nullifier));
        this.nullifiers.push(BigInt(receiver.nullifier));

        return Promise.resolve(true);
    }
}

module.exports = PrivacyPool;