import { expect } from "chai";
import { ethers, zkit } from "hardhat";

import { Poseidon } from "@iden3/js-crypto";

import { time } from "@nomicfoundation/hardhat-network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

import { Identity } from "@/test/helpers/identity";

import { Reverter } from "@/test/helpers/reverter";
import { SECONDS_IN_MONTH } from "@/scripts/utils/constants";

import { buildCredentialId, getMessageHash, getPoseidon, normalizeProof } from "@/test/helpers/zkp";

import {
  AuthenticationStorage,
  Chat,
  ERC1967Proxy__factory,
  ERC721Mock,
  PoseidonSMT,
  PostMessageVerifier,
} from "@ethers-v6";

describe("Chat", () => {
  const reverter = new Reverter();

  let SECOND: SignerWithAddress;

  let secondIdentity: Identity;

  let erc721: ERC721Mock;
  let tree: PoseidonSMT;

  let chat: Chat;
  let authStorage: AuthenticationStorage;

  let postMessageVerifier: PostMessageVerifier;

  before(async () => {
    [SECOND] = await ethers.getSigners();

    const AuthStorage = await ethers.getContractFactory("AuthenticationStorage", {
      libraries: {
        PoseidonUnit3L: await (await getPoseidon(3)).getAddress(),
      },
    });
    authStorage = await AuthStorage.deploy();

    const PoseidonSMT = await ethers.getContractFactory("PoseidonSMT", {
      libraries: {
        PoseidonUnit1L: await (await getPoseidon(1)).getAddress(),
        PoseidonUnit2L: await (await getPoseidon(2)).getAddress(),
        PoseidonUnit3L: await (await getPoseidon(3)).getAddress(),
      },
    });
    tree = await PoseidonSMT.deploy();

    const Chat = await ethers.getContractFactory("Chat");
    chat = await Chat.deploy();

    const Proxy: ERC1967Proxy__factory = await ethers.getContractFactory("ERC1967Proxy");

    let proxy = await Proxy.deploy(await tree.getAddress(), "0x");
    tree = tree.attach(await proxy.getAddress()) as PoseidonSMT;

    const VerifiableCommitmentVerifier = await ethers.getContractFactory("VerifiableCommitmentVerifier");
    const verifier = await VerifiableCommitmentVerifier.deploy();

    proxy = await Proxy.deploy(await authStorage.getAddress(), "0x");
    authStorage = authStorage.attach(await proxy.getAddress()) as AuthenticationStorage;

    await tree.__PoseidonSMT_init(await authStorage.getAddress(), 80);
    await authStorage.__AuthenticationStorage_init(await tree.getAddress(), await verifier.getAddress());

    proxy = await Proxy.deploy(await chat.getAddress(), "0x");
    chat = chat.attach(await proxy.getAddress()) as Chat;

    const PostMessageVerifier = await ethers.getContractFactory("PostMessageVerifier");
    postMessageVerifier = await PostMessageVerifier.deploy();

    await chat.__Chat_init(await tree.getAddress(), await postMessageVerifier.getAddress());

    const ERC721Factory = await ethers.getContractFactory("ERC721Mock");
    erc721 = await ERC721Factory.deploy("ERC721", "ERC721");

    await erc721.mint(SECOND.address, 0);
    secondIdentity = new Identity(ethers.id(SECOND.address));

    await time.increase(SECONDS_IN_MONTH * 12);

    await reverter.snapshot();
  });

  afterEach(reverter.revert);

  describe("#postMessage", () => {
    let creationTimestamp: number;

    beforeEach("setup", async () => {
      const circuit = await zkit.getCircuit("VerifiableCommitment");

      creationTimestamp = (await time.latest()) - 2;
      const deadline = creationTimestamp + 1;

      const data = await circuit.generateProof({
        contractId: await erc721.getAddress(),
        nftId: 0,
        nftOwner: SECOND.address,
        deadline: deadline,
        babyJubJubPK_Ax: secondIdentity.PK.p[0],
        babyJubJubPK_Ay: secondIdentity.PK.p[1],
        timestamp: creationTimestamp,
      });

      const proof = normalizeProof(data);

      await authStorage.register(
        await erc721.getAddress(),
        0,
        SECOND.address,
        ethers.toBeHex(data.publicSignals[0], 32),
        deadline,
        proof,
      );
    });

    it("should post valid message successfully", async () => {
      const circuit = await zkit.getCircuit("PostMessage");

      const validTimeThreshold = creationTimestamp - 1;
      const credentialId = buildCredentialId(
        await erc721.getAddress(),
        0,
        SECOND.address,
        secondIdentity.PK.p[0],
        secondIdentity.PK.p[1],
        creationTimestamp,
      );
      const message = "Hello World!";
      const messageHash = getMessageHash(message);

      const signature = secondIdentity.signHash(BigInt(messageHash));

      const proof = await tree.getProof(ethers.toBeHex(Poseidon.hash([BigInt(credentialId)])));

      const data = await circuit.generateProof({
        contractId: await erc721.getAddress(),
        root: proof.root,
        messageHash,
        expectedMessageTimestamp: validTimeThreshold,
        nftId: 0,
        nftOwner: SECOND.address,
        babyJubJubPK_Ax: secondIdentity.PK.p[0],
        babyJubJubPK_Ay: secondIdentity.PK.p[1],
        timestamp: creationTimestamp,
        siblings: proof.siblings,
        auxKey: proof.auxKey,
        auxValue: proof.auxValue,
        auxIsEmpty: Number(proof.auxExistence),
        isExclusion: 0,
        messageSignatureR8x: signature.R8[0],
        messageSignatureR8y: signature.R8[1],
        messageSignatureS: signature.S,
      });

      const formattedProof = normalizeProof(data);

      expect(
        await circuit.verifyProof({
          proof: {
            pi_a: [String(formattedProof.a[0]), String(formattedProof.a[1])],
            pi_b: [
              [String(formattedProof.b[0][1]), String(formattedProof.b[0][0])],
              [String(formattedProof.b[1][1]), String(formattedProof.b[1][0])],
            ],
            pi_c: [String(formattedProof.c[0]), String(formattedProof.c[1])],
            protocol: "groth16",
            curve: "bn128",
          },
          publicSignals: [data.publicSignals[0], data.publicSignals[1], data.publicSignals[2], data.publicSignals[3]],
        }),
      ).to.be.true;
      expect(
        await postMessageVerifier.verifyProof(formattedProof.a, formattedProof.b, formattedProof.c, [
          data.publicSignals[0],
          data.publicSignals[1],
          data.publicSignals[2],
          data.publicSignals[3],
        ]),
      ).to.be.true;

      await expect(chat.postMessage(erc721.getAddress(), message, proof.root, validTimeThreshold, formattedProof))
        .to.emit(chat, "MessagePosted")
        .withArgs(await erc721.getAddress(), message);

      const messages = await chat.listMessages(erc721.getAddress(), 0, 10);

      expect(messages.length).to.equal(1);
      expect(messages[0].message).to.equal(message);
      expect(messages[0].timestamp).to.equal(await time.latest());
    });

    it("should fail to post message if credential expired", async () => {
      const circuit = await zkit.getCircuit("PostMessage");

      const validTimeThreshold = creationTimestamp;
      const credentialId = buildCredentialId(
        await erc721.getAddress(),
        0,
        SECOND.address,
        secondIdentity.PK.p[0],
        secondIdentity.PK.p[1],
        creationTimestamp,
      );
      const message = "Hello World!";
      const messageHash = getMessageHash(message);

      const signature = secondIdentity.signHash(BigInt(messageHash));

      const proof = await tree.getProof(ethers.toBeHex(Poseidon.hash([BigInt(credentialId)])));

      const data = await circuit.generateProof({
        contractId: await erc721.getAddress(),
        root: proof.root,
        messageHash,
        expectedMessageTimestamp: validTimeThreshold,
        nftId: 0,
        nftOwner: SECOND.address,
        babyJubJubPK_Ax: secondIdentity.PK.p[0],
        babyJubJubPK_Ay: secondIdentity.PK.p[1],
        timestamp: creationTimestamp,
        siblings: proof.siblings,
        auxKey: proof.auxKey,
        auxValue: proof.auxValue,
        auxIsEmpty: Number(proof.auxExistence),
        isExclusion: 0,
        messageSignatureR8x: signature.R8[0],
        messageSignatureR8y: signature.R8[1],
        messageSignatureS: signature.S,
      });

      const formattedProof = normalizeProof(data);

      expect(
        await circuit.verifyProof({
          proof: {
            pi_a: [String(formattedProof.a[0]), String(formattedProof.a[1])],
            pi_b: [
              [String(formattedProof.b[0][1]), String(formattedProof.b[0][0])],
              [String(formattedProof.b[1][1]), String(formattedProof.b[1][0])],
            ],
            pi_c: [String(formattedProof.c[0]), String(formattedProof.c[1])],
            protocol: "groth16",
            curve: "bn128",
          },
          publicSignals: [data.publicSignals[0], data.publicSignals[1], data.publicSignals[2], data.publicSignals[3]],
        }),
      ).to.be.true;
      expect(
        await postMessageVerifier.verifyProof(formattedProof.a, formattedProof.b, formattedProof.c, [
          data.publicSignals[0],
          data.publicSignals[1],
          data.publicSignals[2],
          data.publicSignals[3],
        ]),
      ).to.be.true;

      await time.increase((await chat.LOWER_TIMESTAMP_CHECK()) + 1n);

      await expect(chat.postMessage(erc721.getAddress(), message, proof.root, validTimeThreshold, formattedProof))
        .to.be.revertedWithCustomError(chat, "TimestampCheckpointTooOld")
        .withArgs(validTimeThreshold, BigInt(await time.latest()) - (await chat.LOWER_TIMESTAMP_CHECK()) + 1n);
    });
  });
});
