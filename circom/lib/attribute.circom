include "../../lib/merkleproof.circom"
include "../../lib/circomlib/circuits/comparators.circom"
include "../../lib/circomlib/circuits/poseidon.circom"
include "../../lib/circomlib/circuits/eddsaposeidon.circom"
include "../../lib/circomlib/circuits/gates.circom"

template AttributePresentation(depth, revocDepth) {
		/*
		* Private Inputs
		*/
		// Meta
		signal private input pathMeta[depth];
		signal private input lemmaMeta[depth + 2];
		signal private input meta[8]; //Fixed Size of meta attributes in each credential
		signal private input signatureMeta[3];
		signal private input pathRevocation[revocDepth];
		signal private input lemmaRevocation[revocDepth + 2];
		signal private input revocationLeaf;
		signal private input signChallenge[3];
		signal private input issuerPK[2];
		// Content
		signal private input lemma[depth + 2];
		/*
		* Public Inputs
		*/
		// Meta
		signal input challenge; //6
		signal input expiration; //7
		signal output type; // 0
		signal output revocationRoot; //1
		signal output revoked; //2
		signal output challengeIssuerHash; //3
		signal output deligatable; //4
		// Content
		signal input path[depth]; //8
		signal output attributeHash; //5
		/*
		* Meta calculations
		*/
		type <== meta[1];
		revocationRoot <== lemmaRevocation[revocDepth + 1];
		deligatable <== meta[6];

		component hashMeta[6]; 
		for(var i=0;i<6;i++) {
				hashMeta[i] = Poseidon(1);
		}

		component hashMetaLR[4];
		for(var i=0; i<4; i++) {
				hashMetaLR[i] = HashLeftRight();
		}

		// Check merkle proof
		component merkleProofMeta = MerkleProof(depth);

		merkleProofMeta.lemma[0] <== lemmaMeta[0];
		merkleProofMeta.lemma[depth + 1] <== lemmaMeta[depth + 1];

		for (var i=0;i<depth;i++) {
				merkleProofMeta.path[i] <== pathMeta[i];
				merkleProofMeta.lemma[i + 1] <== lemmaMeta[i + 1];
		}	
		// Check merkle proof signatureMeta
		component eddsaVerify = EdDSAPoseidonVerifier();
		eddsaVerify.enabled <== 1;
		eddsaVerify.Ax <== issuerPK[0];
		eddsaVerify.Ay <== issuerPK[1];
		eddsaVerify.R8x <== signatureMeta[0];
		eddsaVerify.R8y <== signatureMeta[1];
		eddsaVerify.S <== signatureMeta[2];
		eddsaVerify.M <== lemmaMeta[depth + 1];
		// Check meta data by merkle proof	
		// Check id
		hashMeta[0].inputs[0] <== meta[0];
		lemmaMeta[0] === hashMeta[0].out;
		// Check type
		lemmaMeta[1] === meta[1];
		// Check holder key
		meta[2] ==> hashMeta[1].inputs[0];
		meta[3] ==> hashMeta[2].inputs[0];
		hashMetaLR[0].left <== hashMeta[1].out;
		hashMetaLR[0].right <== hashMeta[2].out;
		lemmaMeta[2] === hashMetaLR[0].hash;
		// Check registry and expiration / subtree A
		meta[5] ==> hashMeta[3].inputs[0];
		hashMetaLR[1].left <== meta[4];
		hashMetaLR[1].right <== hashMeta[3].out;
		// Check deligatable and empty object / subtree B
		meta[6] ==> hashMeta[4].inputs[0];
		hashMetaLR[2].left <== hashMeta[4].out;
		// Hash of empty string
		hashMetaLR[2].right <== 19014214495641488759237505126948346942972912379615652741039992445865937985820;
		// Build subtree AB
		hashMetaLR[3].left <== hashMetaLR[1].hash;
		hashMetaLR[3].right <== hashMetaLR[2].hash;
		lemmaMeta[3] === hashMetaLR[3].hash;
		// Check expiration
		component le = LessEqThan(64);
		le.in[0] <== expiration;
		le.in[1] <== meta[5];
		1 === le.out;
		// Check revocation
		// Check leaf index
		signal leafIndex1;
		leafIndex1 <-- meta[0] \ 252;
		var leafIndex2 = 0;
		for (var i=0; i<revocDepth; i++) {
			leafIndex2 += pathRevocation[i] * (2 ** i)
		}
		leafIndex1 === leafIndex2;
		// Check revocation list with merkle proof
		revocationLeaf ==> hashMeta[5].inputs[0];
		hashMeta[5].out === lemmaRevocation[0];
		component merkleProofRevocation = MerkleProof(revocDepth);
		merkleProofRevocation.lemma[0] <== lemmaRevocation[0];
		merkleProofRevocation.lemma[revocDepth + 1] <== lemmaRevocation[revocDepth + 1];
		for (var i=0; i<revocDepth; i++) {
				merkleProofRevocation.path[i] <== pathRevocation[i];
				merkleProofRevocation.lemma[i + 1] <== lemmaRevocation[i + 1];
		}	
		// Check revocation in revocationLeaf
		signal div <-- meta[0] \ 252;
		signal position <-- meta[0] - (252 * div);
		div * 252 + position === meta[0]
		signal div2 <-- revocationLeaf \ (2 ** position);
		div2 * (2 ** position) + (revocationLeaf - (2 ** position * div2)) == revocationLeaf;
		signal div3 <-- div2 \ 2;
		revoked <==  div2 - (2 * div3);
		div3 * 2 + revoked === div2; 
		// Hash challenge issuers ppk
		component hashMeta3 = Poseidon(3);
		challenge ==> hashMeta3.inputs[0];	
		issuerPK[0] ==> hashMeta3.inputs[1];	
		issuerPK[1] ==> hashMeta3.inputs[2];	
		challengeIssuerHash <== hashMeta3.out;
		// Check challenge signature
		component eddsaVerifyChallenge = EdDSAPoseidonVerifier();
		eddsaVerifyChallenge.enabled <== 1;
		eddsaVerifyChallenge.Ax <== meta[2];
		eddsaVerifyChallenge.Ay <== meta[3];
		eddsaVerifyChallenge.R8x <== signChallenge[0];
		eddsaVerifyChallenge.R8y <== signChallenge[1];
		eddsaVerifyChallenge.S <== signChallenge[2];
		eddsaVerifyChallenge.M <== challenge;

		/*
		* Content calculations
		*/
		attributeHash <== lemma[0];
		// check merkle root with merkle root of meta which is already checked
		lemma[depth + 1] === lemmaMeta[depth + 1];
		component merkleProof = MerkleProof(depth);

		merkleProof.lemma[0] <== lemma[0];
		merkleProof.lemma[depth + 1] <== lemma[depth + 1];

		for (var i=0;i<depth;i++) {
				merkleProof.path[i] <== path[i];
				merkleProof.lemma[i + 1] <== lemma[i + 1];
		}	
}

component main = AttributePresentation(4, 13);
