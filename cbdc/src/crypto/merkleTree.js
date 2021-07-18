class MerkleTree {
    /**
     * Simple merkle tree implementation
     * @param input {Array} Leaf elements
     * @param hasher {Function} Hash function for the tree
     * @param [tree] {MerkleTree} Takes merkle tree object and imports tree without checking it for validity,
     * input gets ignored.
     */
    constructor (input, hasher, tree = undefined) {
        this.hasher = hasher;
        if (typeof tree === 'undefined') {
            this.depth = Math.log2(input.length);
            if (this.depth < 1 || this.depth % 1 !== 0) throw "Length of input must be pow of two.";
            this.leaves = input;
            this.data = [];
            this.generateTree();
        } else {
            this.depth = tree.depth;
            this.leaves = tree.leaves;
            this.data = tree.data;
        }
    }

    /**
     * Changes input and recalculates tree hashes after input is changed
     * @param index
     * @param newInput
     */
    update = (index, newInput) => {
        this.leaves[index] = newInput;
        this.generateTree();
    }
    /**
     * Recalculates all tree hashes
     */
    generateTree = () => {
        this.data = [];
        for (let i of this.leaves) {
            this.data.push(this.leafHash(i));
        }
        let width = this.leaves.length;
        width >>= 1;
        let offset = 0;
        while (width > 0) {
            for (let i = 0; i < width; i++) {
                let j = 2 * i + offset;
                this.data.push(this.nodeHash(this.data[j], this.data[j + 1]));
            }
            offset += width * 2;
            width >>= 1;
        }
    }

    nodeHash = (left, right) => {
        return this.hasher([left, right]);
    }

    leafHash = (leaf) => {
        return this.hasher([leaf]);
    }

    /**
     * Builds a merkle proof
     * @param index {Number}
     * @returns {Proof}
     */
    generateProof = (index) => {
        if (this.leaves.length <= index) throw "No valid in index";
        let path = new Array(this.depth).fill(0);
        let base2 = (index).toString(2);
        for (let i = 0; i < base2.length; i++) {
            path[i] = Number(base2[base2.length - i - 1]);
        }
        let lemma = [this.data[index]];
        let offset = 0;
        let pos = index;
        let width = this.leaves.length;
        for (let i = 0; i < this.depth; i++) {
            if (path[i]) {
                lemma.push(this.data[offset + pos - 1]);
            } else {
                lemma.push(this.data[offset + pos + 1]);
            }
            pos >>= 1;
            offset += width;
            width >>= 1;
        }
        lemma.push(this.root);
        return new Proof(path, lemma, this.nodeHash);
    }

    get root() {
        return this.data[this.data.length - 1];
    }

}

class Proof {
    /**
     * A proof of a merkle tree
     * @param path {[Number]}
     * @param lemma {Array}
     * @param nodeHash {Function} Hashing function for a node
     */
    constructor(path, lemma, nodeHash) {
        this.path = path;
        this.lemma = lemma;
        this.nodeHash = nodeHash;
    }

    /**
     * Validates proof
     * @returns {boolean}
     */
    validate() {
        let hash = this.lemma[0];
        for (let i = 0; i < this.path.length; i++) {
            if (this.path[i]) {
               hash = this.nodeHash(this.lemma[i + 1], hash);
            } else {
               hash = this.nodeHash(hash, this.lemma[i + 1]);
            }
        }
        return hash === this.lemma[this.lemma.length - 1];
    }
}

module.exports = MerkleTree;
