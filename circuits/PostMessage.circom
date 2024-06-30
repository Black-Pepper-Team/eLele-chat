pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

include "./SparseMerkleTree.circom";
include "./VerifiableCommitmentTemplate.circom";

template SignatureVerifier() {
    signal input Ax;
    signal input Ay;

    signal input signatureS;
    signal input signatureR8X;
    signal input signatureR8Y;
    signal input data;

    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== Ax;
    sigVerifier.Ay <== Ay;
    sigVerifier.S <== signatureS;
    sigVerifier.R8x <== signatureR8X;
    sigVerifier.R8y <== signatureR8Y;
    sigVerifier.M <== data;
}


template PostMessage(levels) {
    // Public
    signal input contractId;
    signal input root;
    signal input messageHash;
    signal input expectedMessageTimestamp;

    // Private
    signal input nftId;
    signal input nftOwner;
    signal input babyJubJubPK_Ax;
    signal input babyJubJubPK_Ay;
    signal input timestamp;

    signal input siblings[levels];

    signal input auxKey;
    signal input auxValue;
    // 1 if the aux node is empty, 0 otherwise
    signal input auxIsEmpty;

    // 1 if we are checking for exclusion, 0 if we are checking for inclusion
    signal input isExclusion;

    signal input messageSignatureR8x;
    signal input messageSignatureR8y;
    signal input messageSignatureS;

    // ----------------------------------- Logic -----------------------------------

    component credBuild = BuildVerifiableCommitment();
    credBuild.contractId <== contractId;
    credBuild.nftId <== nftId;
    credBuild.nftOwner <== nftOwner;

    credBuild.babyJubJubPK_Ax <== babyJubJubPK_Ax;
    credBuild.babyJubJubPK_Ay <== babyJubJubPK_Ay;
    credBuild.timestamp <== timestamp;

    signal computedCredId <== credBuild.credentialId;

    component smtVerifier = SparseMerkleTreeVerifier(levels);
    smtVerifier.siblings <== siblings;

    component leafHasher = Poseidon(1);
    leafHasher.inputs[0] <== computedCredId;

    smtVerifier.key <== leafHasher.out;

    component computedCredValue = Poseidon(3);
    computedCredValue.inputs[0] <== contractId;
    computedCredValue.inputs[1] <== nftId;
    computedCredValue.inputs[2] <== nftOwner;

    smtVerifier.value <== computedCredValue.out;

    smtVerifier.auxKey <== auxKey;
    smtVerifier.auxValue <== auxValue;
    smtVerifier.auxIsEmpty <== auxIsEmpty;

    smtVerifier.isExclusion <== isExclusion;

    smtVerifier.root <== root;

    component sigVerifier = SignatureVerifier();
    sigVerifier.Ax <== babyJubJubPK_Ax;
    sigVerifier.Ay <== babyJubJubPK_Ay;
    sigVerifier.signatureS <== messageSignatureS;
    sigVerifier.signatureR8X <== messageSignatureR8x;
    sigVerifier.signatureR8Y <== messageSignatureR8y;
    sigVerifier.data <== messageHash;

    component greaterEqThanUpperTime = GreaterEqThan(64); // compare up to 2**64
    greaterEqThanUpperTime.in[0] <== timestamp;
    greaterEqThanUpperTime.in[1] <== expectedMessageTimestamp;

    component timestampUpperBoundCheck = ForceEqualIfEnabled();
    timestampUpperBoundCheck.in[0] <== greaterEqThanUpperTime.out;
    timestampUpperBoundCheck.in[1] <== 1;
    timestampUpperBoundCheck.enabled <== 1;
}

component main {
    public [contractId, root, messageHash, expectedMessageTimestamp]
} = PostMessage(80);
