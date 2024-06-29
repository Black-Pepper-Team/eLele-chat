pragma circom 2.0.0;

include "./VerifiableCommitmentTemplate.circom";

component main { public [contractId, nftId, nftOwner, deadline] } = VerifiableCommitment();
