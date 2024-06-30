pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template BuildVerifiableCommitment() {
    signal output credentialId; 

    // Public signals
    signal input contractId;
    signal input nftId;
    signal input nftOwner;

    // Private signals
    signal input babyJubJubPK_Ax;
    signal input babyJubJubPK_Ay;

    signal input timestamp;

    component computedCredId = Poseidon(6);
    computedCredId.inputs[0] <== contractId;
    computedCredId.inputs[1] <== nftId;
    computedCredId.inputs[2] <== nftOwner;
    computedCredId.inputs[3] <== babyJubJubPK_Ax;
    computedCredId.inputs[4] <== babyJubJubPK_Ay;
    computedCredId.inputs[5] <== timestamp;

    credentialId <== computedCredId.out;
}

template VerifiableCommitment() {
    signal output credentialId;

    // Public signals
    signal input contractId;
    signal input nftId;
    signal input nftOwner;
    signal input deadline;

    // Private signals
    signal input babyJubJubPK_Ax;
    signal input babyJubJubPK_Ay;

    signal input timestamp;

    component credBuild = BuildVerifiableCommitment();
    credBuild.contractId <== contractId;
    credBuild.nftId <== nftId;
    credBuild.nftOwner <== nftOwner;
    credBuild.babyJubJubPK_Ax <== babyJubJubPK_Ax;
    credBuild.babyJubJubPK_Ay <== babyJubJubPK_Ay;
    credBuild.timestamp <== timestamp;

    credentialId <== credBuild.credentialId;

    component greaterEqThanLowerTime = GreaterEqThan(64); // compare up to 2**64
    greaterEqThanLowerTime.in[0] <== deadline;
    greaterEqThanLowerTime.in[1] <== timestamp;

    component timestampLowerboundCheck = ForceEqualIfEnabled();
    timestampLowerboundCheck.in[0] <== greaterEqThanLowerTime.out;
    timestampLowerboundCheck.in[1] <== 1;
    timestampLowerboundCheck.enabled <== 1;

    component greaterEqThanUpperTime = GreaterEqThan(64); // compare up to 2**64
    greaterEqThanUpperTime.in[0] <== timestamp + 500;
    greaterEqThanUpperTime.in[1] <== deadline;

    component timestampUpperBoundCheck = ForceEqualIfEnabled();
    timestampUpperBoundCheck.in[0] <== greaterEqThanUpperTime.out;
    timestampUpperBoundCheck.in[1] <== 1;
    timestampUpperBoundCheck.enabled <== 1;
}
