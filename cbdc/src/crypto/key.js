const {prv2pub} = require('../../lib/circomlib/src/eddsa.js');

class EdDSAKey {
    /**
     * Generates new random secret key based on Math.random()
     * @returns {string}
     */
    static newKey = () => {
        return BigInt(Math.floor(Math.random() * Math.pow(10, 64))).toString();
    }

    /**
     * Generates public key from secret
     * @param sk {String} secret key
     * @returns {[BigInt]}
     */
    static getPublicKey = (sk) => {
        return prv2pub(sk);
    }
}

module.exports = {EdDSAKey};