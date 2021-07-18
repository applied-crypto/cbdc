include "./circomlib/circuits/eddsaposeidon.circom"
include "./circomlib/circuits/poseidon.circom"
include "./merkleproof.circom"
include "./circomlib/circuits/comparators.circom"

template CheckMetaDataIntegrity(depth) {
    signal input path[depth];
    signal input lemma[depth + 2];
    signal input meta[8];
    signal input signatureMeta[3];
    signal input issuerPK[2];


    signal output id;
    signal output type;
    signal output holderPK[2];
    signal output revocationRegistry;
    signal output expiration;
    signal output delegatable;
    signal output credentialRoot;

    component hash[5]; 
    for (var i = 0; i < 5; i++) {
            hash[i] = Poseidon(1);
    }

    component eddsaVerify = EdDSAPoseidonVerifier();
    eddsaVerify.enabled <== 1;
    eddsaVerify.Ax <== issuerPK[0];
    eddsaVerify.Ay <== issuerPK[1];
    eddsaVerify.R8x <== signatureMeta[0];
    eddsaVerify.R8y <== signatureMeta[1];
    eddsaVerify.S <== signatureMeta[2];
    eddsaVerify.M <== lemma[depth + 1];

    component merkleTree = MerkleTree(3);

    hash[0].inputs[0] <== meta[0]
    merkleTree.data[0] <== hash[0].out; 

    merkleTree.data[1] <== meta[1];

    hash[1].inputs[0] <== meta[2];
    merkleTree.data[2] <== hash[1].out;

    hash[2].inputs[0] <== meta[3];
    merkleTree.data[3] <== hash[2].out;

    merkleTree.data[4] <== meta[4];

    hash[3].inputs[0] <== meta[5];
    merkleTree.data[5] <== hash[3].out;

    hash[4].inputs[0] <== meta[6];
    merkleTree.data[6] <== hash[4].out;
    
    merkleTree.data[7] <== 19014214495641488759237505126948346942972912379615652741039992445865937985820; 

    component merkleProofMeta = MerkleProof(depth - 3);
    merkleProofMeta.lemma[0] <== merkleTree.root;
    merkleProofMeta.lemma[depth - 3 + 1] <== lemma[depth + 1];
    for (var i = 0; i < depth - 3; i++) {
        merkleProofMeta.path[i] <== path[3 + i];
        merkleProofMeta.lemma[i + 1] <== lemma[3 + i + 1];
    }

    id <== meta[0];
    type <== meta[1];
    holderPK[0] <== meta[2];
    holderPK[1] <== meta[3];
    revocationRegistry <== meta[4];
    expiration <== meta[5];
    delegatable <== meta[6];
    credentialRoot <== lemma[depth + 1];
}

template CheckExpiration() {
    signal input expirationCredential;
    signal input expirationPresentation;

    component le = LessEqThan(64);
    le.in[0] <== expirationPresentation;
    le.in[1] <== expirationCredential
    1 === le.out;
}

template Pow(n) {
    signal input base;
    signal input exponent; 

    signal output out;

    signal power[n + 1];
    signal tmp[n];
    signal tmp2[n];
    component le[n];

    power[0] <== 1;
    for (var i = 0; i < n; i++) {
        le[i] = LessEqThan(8);
        le[i].in[0] <== i + 1;
        le[i].in[1] <== exponent;
        tmp[i] <== power[i] * base;
        tmp2[i] <== (1 - le[i].out) * power[i];
        power[i + 1] <== tmp2[i] + le[i].out * tmp[i];
    }

    out <== power[n];
}

template Div(n) {
    signal input num;
    signal input denum;

    signal output div;
    signal output mod;

    div <-- (denum != 0) ? num \ denum : 0;
    mod <-- (denum != 0) ? num % denum : 0; 
    
    component le = LessThan(n);
    le.in[0] <== mod;
    le.in[1] <== denum;
    le.out === 1;

    num === div * denum + mod;
}

template CheckRevocation(depth) {
    signal input id;
    signal input lemma[depth + 2];
    signal input path[depth];
    signal input revocationLeaf;

    signal output revoked;
    signal output revocationRoot;

    component div[4];
    for (var i = 0; i < 4; i++) {
        div[i] = Div(252);
    }

    signal leafIndex[depth];
    component powLeafIndex[depth - 1];
    div[0].num <== id;
    div[0].denum <== 252;

    leafIndex[0] <== path[0];
    for(var i = 0; i < (depth - 1); i++) {
        powLeafIndex[i] = Pow(depth);
        powLeafIndex[i].base <== 2;
        powLeafIndex[i].exponent <== i + 1;
        leafIndex[i + 1] <== leafIndex[i] + path[i + 1] * powLeafIndex[i].out;
    }

    leafIndex[depth - 1] === div[0].div;

    component hash; 
    hash = Poseidon(1);
    hash.inputs[0] <== revocationLeaf;
    hash.out === lemma[0];
    component merkleProof = MerkleProof(depth);
    merkleProof.lemma[0] <== lemma[0];
    merkleProof.lemma[depth + 1] <== lemma[depth + 1];
    for (var i = 0; i < depth; i++) {
            merkleProof.path[i] <== path[i];
            merkleProof.lemma[i + 1] <== lemma[i + 1];
    }	

    component pow = Pow(252);
    pow.base <== 2;
    pow.exponent <== div[0].mod;
    div[2].num <== revocationLeaf;
    div[2].denum <== pow.out;
    div[3].num <== div[2].div;
    div[3].denum <== 2;

    revoked <== div[3].mod;

    revocationRoot <== lemma[depth + 1];
}

template Link() {
    signal input pk[2];
    signal input challenge;

    signal output out;

    component hash = Poseidon(3);
	hash.inputs[0] <== challenge;	
	hash.inputs[1] <== pk[0];
	hash.inputs[2] <== pk[1];	
	out <== hash.out;
}