pragma circom 2.0.0;

//include "../../cbdc/lib/circomlib/circuits/poseidon.circom";
//include "../../cbdc/lib/circomlib/circuits/eddsaposeidon.circom";
//include "../lib/merkleproof.circom";
include "../../../../heimdall/circom/presentations/attribute/circuit.circom";

template PrivacyPool(commitmentsDepth) {
    var depthCredential = 4;
    var revocationDepth = 13;

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
    signal input expiration;
    signal input challenge;

    signal output type; // 0
    signal output revocationRoot; //1
    signal output revocationRegistry; //2
    signal output revoked; //3
    signal output linkBack; //4
    signal output delegatable; //5
    signal output attributeHash;

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

    type <== attributePresentation.type;
    revocationRoot <== attributePresentation.revocationRoot;
    revocationRegistry <== attributePresentation.revocationRegistry;
    revoked <== attributePresentation.revoked;
    linkBack <== attributePresentation.linkBack;
    delegatable <== attributePresentation.delegatable;
    attributeHash <== attributePresentation.attributeHash;
}


component main = PrivacyPool(5);