include "./merkleproof.circom"
include "./circomlib/circuits/comparators.circom"
include "./circomlib/circuits/poseidon.circom"
include "./circomlib/circuits/eddsaposeidon.circom"
include "./lib/circomlib/circuits/gates.circom"

template MetaPresentation(depth) {
		signal private input pathMeta[depth];
		signal private input lemmaMeta[depth + 2];
		//Fixed Size of meta attributes in each credential
		signal private input meta[8];
		signal private input signature[3];
		signal private input issuerPK[2];
		signal private input pathRevocation[4];
		signal private input lemmaRevocation[4 + 2];
		signal private input revocationLeaf;
		signal private input signChallenge[3];

		signal input challenge;
		signal input expiration;
		signal output type <== meta[1];
		signal output revocationRoot <== lemmaRevocation[4 + 1];
		signal output revoced;
		signal output challengeIssuerHash;

		component hash[6]; 
		for(var i=0;i<6;i++) {
				hash[i] = Poseidon(1);
		}

		component hashLR[4];
		for(var i=0; i<4; i++) {
				hashLR[i] = HashLeftRight();
		}

		//
		// Check merkle proof
		//
		component merkleProofMeta = MerkleProof(depth);

		merkleProofMeta.lemma[0] <== lemmaMeta[0];
		merkleProofMeta.lemma[depth + 1] <== lemmaMeta[depth + 1];

		for (var i=0;i<depth;i++) {
				merkleProofMeta.path[i] <== pathMeta[i];
				merkleProofMeta.lemma[i + 1] <== lemmaMeta[i + 1];
		}	
		//
		// Check merkle proof signature
		//
		component eddsaVerify = EdDSAPoseidonVerifier();
		eddsaVerify.enabled <== 1;
		eddsaVerify.Ax <== issuerPK[0];
		eddsaVerify.Ay <== issuerPK[1];
		eddsaVerify.R8x <== signature[0];
		eddsaVerify.R8y <== signature[1];
		eddsaVerify.S <== signature[2];
		eddsaVerify.M <== lemmaMeta[depth + 1];
		//
		// Check meta data by merkle proof	
		//
		// Check id
		hash[0].inputs[0] <== meta[0];
		lemmaMeta[0] === hash[0].out;
		// Check type
		lemmaMeta[1] === meta[1];
		// Check holder key
		meta[2] ==> hash[1].inputs[0];
		meta[3] ==> hash[2].inputs[0];
		hashLR[0].left <== hash[1].out;
		hashLR[0].right <== hash[2].out;
		lemmaMeta[2] === hashLR[0].hash;
		// Check registry and expiration / subtree A
		meta[5] ==> hash[3].inputs[0];
		hashLR[1].left <== meta[4];
		hashLR[1].right <== hash[3].out;
		// Check delegatable and empty object / subtree B
		meta[6] ==> hash[4].inputs[0];
		hashLR[2].left <== hash[4].out;
		// Hash of empty string
		hashLR[2].right <== 12404765264677785452483002305892888278079468280430919726508528749824526870360;
		// Build subtree AB
		hashLR[3].left <== hashLR[1].hash;
		hashLR[3].right <== hashLR[2].hash;
		lemmaMeta[3] === hashLR[3].hash;
		//
		// Check expiration
		//
		component le = LessEqThan(64);
		le.in[0] <== expiration;
		le.in[1] <== meta[5];
		1 === le.out;
		//
		// Check revocation
		//
		// Check revocation list with merkle proof
		revocationLeaf ==> hash[5].inputs[0];
		hash[5].out === lemmaRevocation[0];
		component merkleProofRevocation = MerkleProof(4);
		merkleProofRevocation.lemma[0] <== lemmaRevocation[0];
		merkleProofRevocation.lemma[depth + 1] <== lemmaRevocation[depth + 1];
		for (var i=0; i<depth; i++) {
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
		revoced <==  div2 - (2 * div3);
		div3 * 2 + revoced === div2;
		//
		// Verify the signature of the challenge
		//
		component eddsaVerifyChallenge = EdDSAPoseidonVerifier();
		eddsaVerifyChallenge.enabled <== 1;
		eddsaVerifyChallenge.Ax <== meta[2];
		eddsaVerifyChallenge.Ay <== meta[3];
		eddsaVerifyChallenge.R8x <== signChallenge[0];
		eddsaVerifyChallenge.R8y <== signChallenge[1];
		eddsaVerifyChallenge.S <== signChallenge[2];
		eddsaVerifyChallenge.M <== challenge;
		//
		// Hash challenge issuers ppk
		//
		component hash3 = Poseidon(3);
		challenge ==> hash3.inputs[0];	
		issuerPK[0] ==> hash3.inputs[1];	
		issuerPK[1] ==> hash3.inputs[2];	
		challengeIssuerHash <== hash3.out;
}

component main = MetaPresentation(4);
