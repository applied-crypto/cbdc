pragma circom 2.0.0;

//include "../../cbdc/lib/circomlib/circuits/poseidon.circom";
//include "../../cbdc/lib/circomlib/circuits/eddsaposeidon.circom";
//include "../lib/merkleproof.circom";
include "../../../heimdall/circom/presentations/attribute/circuit.circom";

template PrivacyPool(commitmentsDepth) {
    var depthCredential = 4;
    var revocationDepth = 13;

	signal input previousCommitmentInput[8];
	signal input previousCommitmentSignature[3];
	signal input pathPreviousCommitment[commitmentsDepth];
	signal input lemmaPreviousCommitment[commitmentsDepth + 2];
	signal input sessionNumber;
	signal input amount;
	signal input publicKey[2];
	signal input nullifierSignature[3];
	signal input nextCommitmentSessionNumber;
	signal input nextCommitmentSignature[3];
	signal input receiver; // 5
	signal input timestamp; // 6
	signal input expiration;
	signal input challenge;

    signal input pathMeta[depthCredential];
    signal input lemmaMeta[depthCredential + 2];
    signal input meta[8];
    signal input signatureMeta[3];
    signal input pathRevocation[revocationDepth];
    signal input lemmaRevocation[revocationDepth + 2];
    signal input revocationLeaf;
    signal input signChallenge[3];
    signal input issuerPK[2];
    signal input lemma[depthCredential + 2];
    signal input path[depthCredential];

	signal output root; // 0
	signal output linkTransfer; // 1
	signal output linkNationality; // 2
	signal output nullifier; // 3
	signal output nextCommitment; // 4

	var EPOCH_TURNOVER_INTERVAL = 2592000; // 30 * 24 * 60 * 60
	var EPOCH_TURNOVER = 150;

	component attributePresentation = AttributePresentation(depthCredential, revocationDepth);

    for(var i = 0; i < depthCredential; i++){
	    attributePresentation.pathMeta[i] <== pathMeta[i];
        attributePresentation.lemmaMeta[i] <== lemmaMeta[i];
        attributePresentation.lemma[i] <== lemma[i];
	    attributePresentation.path[i] <== path[i];
    }

    attributePresentation.lemmaMeta[depthCredential] <== lemmaMeta[depthCredential];
    attributePresentation.lemmaMeta[depthCredential + 1] <== lemmaMeta[depthCredential + 1];
    attributePresentation.lemma[depthCredential] <== lemma[depthCredential];
    attributePresentation.lemma[depthCredential + 1] <== lemma[depthCredential + 1];

    for(var i = 0; i < 8; i++){
        attributePresentation.meta[i] <== meta[i];
    }

    for(var i = 0; i < 3; i++){
        attributePresentation.signatureMeta[i] <== signatureMeta[i];
        attributePresentation.signChallenge[i] <== signChallenge[i];
    }

    for(var i = 0; i < revocationDepth; i++) {
        attributePresentation.pathRevocation[i] <== pathRevocation[i];
        attributePresentation.lemmaRevocation[i] <== lemmaRevocation[i];
    }

    attributePresentation.lemmaRevocation[revocationDepth] <== lemmaRevocation[revocationDepth];
    attributePresentation.lemmaRevocation[revocationDepth + 1] <== lemmaRevocation[revocationDepth + 1];

    attributePresentation.revocationLeaf <== revocationLeaf;
    attributePresentation.issuerPK[0] <== issuerPK[0];
    attributePresentation.issuerPK[1] <== issuerPK[1];
    attributePresentation.expiration <== expiration;
    attributePresentation.challenge <== challenge;

    //signal output type <== attributePresentation.type;
    signal output revocationRoot <== attributePresentation.revocationRoot;
    signal output revocationRegistry <== attributePresentation.revocationRegistry;
    //signal output revoked <== attributePresentation.revoked;
    //signal output linkBack <== attributePresentation.linkBack;
    //signal output delegatable <== attributePresentation.delegatable;
    //signal output attributeHash <== attributePresentation.attributeHash;

    6936141895847827773039820306011898011976769516186037164536571405943971461449 === attributePresentation.type;
    0 === attributePresentation.revoked;

	component poseidonHash = Poseidon(1);
	poseidonHash.inputs[0] <== publicKey[0];
    poseidonHash.out === attributePresentation.attributeHash;

	var hashNumber = 11;
	component hash[hashNumber];
	for(var i = 0; i < hashNumber; i++) {
		hash[i] = Poseidon(1);
	}
	// Building tree of previous commitment
	hash[0].inputs[0] <== previousCommitmentInput[1];
	hash[1].inputs[0] <== previousCommitmentInput[2];
	hash[2].inputs[0] <== previousCommitmentInput[3];
	hash[3].inputs[0] <== previousCommitmentInput[4];
	hash[4].inputs[0] <== previousCommitmentInput[5];

	component merkleTree = MerkleTree(3);

	merkleTree.data[0] <== previousCommitmentInput[0];
	for(var i = 0; i < 5; i++) {
		merkleTree.data[i + 1] <== hash[i].out;
	}
	merkleTree.data[6] <== previousCommitmentInput[6];
	merkleTree.data[7] <== previousCommitmentInput[7];

	// Verifying signature of previous commitment
	component previousCommitmentEdDSA = EdDSAPoseidonVerifier();
	previousCommitmentEdDSA.enabled <== 1;
	previousCommitmentEdDSA.Ax <== publicKey[0];
	previousCommitmentEdDSA.Ay <== publicKey[1];
	previousCommitmentEdDSA.R8x <== previousCommitmentSignature[0];
	previousCommitmentEdDSA.R8y <== previousCommitmentSignature[1];
	previousCommitmentEdDSA.S <== previousCommitmentSignature[2];
	previousCommitmentEdDSA.M <== merkleTree.root;

	// Hashing signature
	component hashPreviousCommitmentSignature = Poseidon(3);
	hashPreviousCommitmentSignature.inputs[0] <== previousCommitmentSignature[0];
	hashPreviousCommitmentSignature.inputs[1] <== previousCommitmentSignature[1];
	hashPreviousCommitmentSignature.inputs[2] <== previousCommitmentSignature[2];

	// Lemma is the hashed leaf --> hash the hashed signature again
	hash[5].inputs[0] <== hashPreviousCommitmentSignature.out;
	hash[5].out === lemmaPreviousCommitment[0];

	// Checking the merkle proof
	component merkleProof = MerkleProof(commitmentsDepth);

	merkleProof.lemma[0] <== lemmaPreviousCommitment[0];
	merkleProof.lemma[1] <== lemmaPreviousCommitment[1];
	for(var i = 0; i < commitmentsDepth; i++) {
		merkleProof.lemma[i + 2] <== lemmaPreviousCommitment[i + 2];
		merkleProof.path[i] <== pathPreviousCommitment[i];
	}

	root <== lemmaPreviousCommitment[commitmentsDepth + 1];

	// Verifying signature of nullifier 
	component nullifierEdDSA = EdDSAPoseidonVerifier();
	nullifierEdDSA.enabled <== 1;
	nullifierEdDSA.Ax <== publicKey[0];
	nullifierEdDSA.Ay <== publicKey[1];
	nullifierEdDSA.R8x <== nullifierSignature[0];
	nullifierEdDSA.R8y <== nullifierSignature[1];
	nullifierEdDSA.S <== nullifierSignature[2];
	nullifierEdDSA.M <== hash[0].out;

	component hashNullifier = Poseidon(3);
	hashNullifier.inputs[0] <== nullifierSignature[0];
	hashNullifier.inputs[1] <== nullifierSignature[1];
	hashNullifier.inputs[2] <== nullifierSignature[2];
	nullifier <== hashNullifier.out;

	// Create Links
	component hashTwo[2];
	for(var i = 0; i < 2; i++) {
		hashTwo[i] = Poseidon(2);
	}
	hashTwo[0].inputs[0] <== sessionNumber;
	hashTwo[0].inputs[1] <== amount;
	linkTransfer <== hashTwo[0].out;
	
	hashTwo[1].inputs[0] <== sessionNumber;
	hashTwo[1].inputs[1] <== previousCommitmentInput[1];
	linkNationality <== hashTwo[1].out;

	// Check if balance of sender is greater equal amount
	component gET[2] ;
	gET[0] = GreaterEqThan(32);
	gET[0].in[0] <== previousCommitmentInput[2];
	gET[0].in[1] <== amount;

	(1 - gET[0].out) * (1 - receiver) === 0;

	// Check epoch turnover

	signal timeDifference <== timestamp - previousCommitmentInput[4];
	// Check if epoch is over
	gET[1] = GreaterEqThan(32);
	gET[1].in[0] <== timeDifference;
	gET[1].in[1] <== EPOCH_TURNOVER;
	// if epoch is over new timestamp is last reset, else old 
	signal newLastResetTmp <== gET[1].out * timestamp;
	signal newLastReset <== previousCommitmentInput[4] * (1 - gET[1].out) + newLastResetTmp;
	// calculates amount of epoch, if epoch is over it start at zero, otherwise at the previouse commitments value
	signal newEpoch <== (1 - gET[1].out) * previousCommitmentInput[3] + amount;
	// Check if the amount of the turnover is smaller than EPOCH_TURNOVER
	component lET = LessEqThan(32);
	lET.in[0] <== newEpoch;
	lET.in[1] <== EPOCH_TURNOVER;
	lET.out === 1;

	// Building tree of next commitment
	hash[6].inputs[0] <== previousCommitmentInput[1] + 1;
	hash[7].inputs[0] <== previousCommitmentInput[2] + (2 * receiver - 1) * amount;
	hash[8].inputs[0] <== newEpoch;
	hash[9].inputs[0] <== newLastReset;
	hash[10].inputs[0] <== nextCommitmentSessionNumber;

	component merkleTreeNextCommitment = MerkleTree(3);

	merkleTreeNextCommitment.data[0] <== previousCommitmentInput[0];
	for(var i = 0; i < 5; i++) {
		merkleTreeNextCommitment.data[i + 1] <== hash[i + 6].out;
	}
	merkleTreeNextCommitment.data[6] <== previousCommitmentInput[6];
	merkleTreeNextCommitment.data[7] <== previousCommitmentInput[7];

	// Verifying signature of next commitment
	component nextCommitmentEdDSA = EdDSAPoseidonVerifier();
	nextCommitmentEdDSA.enabled <== 1;
	nextCommitmentEdDSA.Ax <== publicKey[0];
	nextCommitmentEdDSA.Ay <== publicKey[1];
	nextCommitmentEdDSA.R8x <== nextCommitmentSignature[0];
	nextCommitmentEdDSA.R8y <== nextCommitmentSignature[1];
	nextCommitmentEdDSA.S <== nextCommitmentSignature[2];
	nextCommitmentEdDSA.M <== merkleTreeNextCommitment.root;

    component hashNextCommitment;
    hashNextCommitment = Poseidon(3);
    hashNextCommitment.inputs[0] <== nextCommitmentEdDSA.R8x;
    hashNextCommitment.inputs[1] <== nextCommitmentEdDSA.R8y;
    hashNextCommitment.inputs[2] <== nextCommitmentEdDSA.S;
	nextCommitment <== hashNextCommitment.out;

}


component main {public [receiver, timestamp]} = PrivacyPool(5);