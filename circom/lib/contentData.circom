include "./merkleproof.circom"
include "./polygon.circom"

template CheckAttribute(depth) {
    signal input lemma[depth + 2];
    signal input path[depth];
    signal input credentialRoot;

    signal output attribute;

    lemma[depth + 1] === credentialRoot;

    component merkleProof = MerkleProof(depth);

    merkleProof.lemma[0] <== lemma[0];
    merkleProof.lemma[depth + 1] <== lemma[depth + 1];

    for (var i=0;i<depth;i++) {
            merkleProof.path[i] <== path[i];
            merkleProof.lemma[i + 1] <== lemma[i + 1];
    }	

    attribute <== lemma[0];
}

template CheckPolygon(polygonSize, depth) {
    signal input location[2];
    signal input lemma[depth + 2];
    signal input path[depth];
    signal input vertx[polygonSize];
    signal input verty[polygonSize];
    signal input credentialRoot;

    signal output inbound;
    
    component hash[2];
    hash[0] = Poseidon(1);
    hash[1] = Poseidon(1);
    hash[0].inputs[0] <== location[0];
    hash[1].inputs[0] <== location[1];
    
    lemma[0] === hash[0].out;
    lemma[1] === hash[1].out;
    lemma[depth + 1] === credentialRoot;
    
    component merkleProof = MerkleProof(depth);

    merkleProof.lemma[0] <== lemma[0];
    merkleProof.lemma[depth + 1] <== lemma[depth + 1];

    for (var i=0;i<depth;i++) {
            merkleProof.path[i] <== path[i];
            merkleProof.lemma[i + 1] <== lemma[i + 1];
    }	
            
    component polygon = Polygon(polygonSize);

    for(var i = 0; i < polygonSize; i++) {
        polygon.vertx[i] <== vertx[i];
        polygon.verty[i] <== verty[i];
    }		

    polygon.testx <== location[0];
    polygon.testy <== location[1];

    inbound <== polygon.out;
}