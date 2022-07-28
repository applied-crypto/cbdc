const Account = require('./src/account')
const PrivacyPool = require("./src/privacyPool");
//const Credential = require("../../heimdall/heimdalljs/src/credential");
//const newKey = require("../../heimdall/heimdalljs/src/crypto/key");
//const {merkleTree} = require("../../heimdall/heimdalljs/src/crypto/merkleTree");
//const {getPublicKey} = require("../../heimdall/heimdalljs/src/crypto/key");
//const {signPoseidon} = require(".../../heimdall/heimdalljs/circomlib/eddsa.js");
const {Key, Credential, merklePoseidon, signPoseidon, RevocationRegistry} = require("../heimdall/heimdalljs");
const {getTimestamp} = require("./src/util");

let main = async () => {
    // Creating new privacy Pool
    let privacyPool = new PrivacyPool();

    // Creating revocation Registry
    let skIDIssuer = Key.newKey(1234);
    let revocationRegistry = new RevocationRegistry(skIDIssuer, merklePoseidon,
        (sk, msg) => signPoseidon(sk, BigInt(msg)));

    // Creating two accounts
    let p1 = new Account(1000, "Germany", 1234);
    let expiration = getTimestamp() + 60 * 60 * 24 * 365;
    p1.id = new Credential(
        [
            "John",
            "Jones",
            "male",
            "843995700",
            "blue",
            "180",
            "115703781",
            "499422598"
        ],
        1,
        p1.publicKey,
        expiration,
        "IdentityCard",
        0,
        "RevocationRegistry",
        skIDIssuer,
        merklePoseidon,
        signPoseidon,
        Key.getPublicKey
    );

    let p2 = new Account(1000, "Germany", 1234);

    p2.id = new Credential(
        [
            "Max",
            "Mustermann",
            "male",
            "843995700",
            "blue",
            "186",
            "115703781",
            "499422598"
        ],
        2,
        p2.publicKey,
        expiration,
        "IdentityCard",
        0,
        "RevocationRegistry",
        skIDIssuer,
        merklePoseidon,
        signPoseidon,
        Key.getPublicKey
    );

    // Onboarding the accounts
    privacyPool.onboard(p1.commitment);
    privacyPool.onboard(p2.commitment);

    // Fully private transaction
    let update1 = await p1.update(-10, privacyPool, 1234567890, revocationRegistry).catch(console.log);


    let update2 = await p2.update(10, privacyPool, 1234567890, revocationRegistry).catch(console.log);
    await privacyPool.update(update1, update2, revocationRegistry).catch(console.log);

    // Fully private transaction
    let update3 = await p1.update(-10, privacyPool, 9876543210, revocationRegistry).catch(console.log);
    let update4 = await p2.update(10, privacyPool, 9876543210, revocationRegistry).catch(console.log);
    await privacyPool.update(update3, update4, revocationRegistry).catch(console.log);

    console.log("What the central bank sees:", privacyPool.commitments, privacyPool.nullifiers);
    console.log("What person 1 sees:", p1);
    console.log("What person 2 sees:", p2);

    process.exit();
}

main();
