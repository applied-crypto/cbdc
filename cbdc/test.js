const Account = require('./src/account')
const PrivacyPool = require("./src/privacyPool");


let main = async () => {
    // Creating new privacy Pool
    let privacyPool = new PrivacyPool();

    // Creating two accounts
    let p1 = new Account(1000, "Germany", 1234);
    let p2 = new Account(1000, "Germany", 1234);

    // Onboarding the accounts
    privacyPool.onboard(p1.commitment);
    privacyPool.onboard(p2.commitment);

    // Fully private transaction
    let update1 = await p1.update(-10, privacyPool, 1234567890).catch(console.log);
    let update2 = await p2.update(10, privacyPool, 1234567890).catch(console.log);
    await privacyPool.update(update1, update2).catch(console.log);

    // Fully private transaction
    let update3 = await p1.update(-10, privacyPool, 9876543210).catch(console.log);
    let update4 = await p2.update(10, privacyPool, 9876543210).catch(console.log);
    await privacyPool.update(update3, update4).catch(console.log);

    console.log("What the central bank sees:", privacyPool.commitments, privacyPool.nullifiers);
    console.log("What person 1 sees:", p1);
    console.log("What person 2 sees:", p2);

    process.exit();
}

main();
