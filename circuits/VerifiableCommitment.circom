pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template VerifiableCommitment() {
    signal output credentialId;

    // Public signals
    signal input contractId;
    signal input nftId;
    signal input nftOwner;
    signal input deadline;

    // Private signals
    signal input babyJubJubPK;
    signal input timestamp;

    component computedCredId = Poseidon(5);
    computedCredId.inputs[0] <== contractId;
    computedCredId.inputs[1] <== nftId;
    computedCredId.inputs[2] <== nftOwner;
    computedCredId.inputs[3] <== babyJubJubPK;
    computedCredId.inputs[4] <== timestamp;

    credentialId <== computedCredId.out;

    component greaterEqThanLowerTime = GreaterEqThan(64); // compare up to 2**64
    greaterEqThanLowerTime.in[0] <== timestamp;
    greaterEqThanLowerTime.in[1] <== deadline;
}

component main { public [contractId, nftId, nftOwner, deadline] } = VerifiableCommitment();
