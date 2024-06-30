import { expect } from "chai";
import { ethers, zkit } from "hardhat";

import { time } from "@nomicfoundation/hardhat-network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

import { Identity } from "@/test/helpers/identity";
import { Reverter } from "@/test/helpers/reverter";
import { getPoseidon, normalizeProof } from "@/test/helpers/zkp";

import { SECONDS_IN_MONTH } from "@/scripts/utils/constants";

import { AuthenticationStorage, ERC1967Proxy__factory, ERC721Mock, PoseidonSMT } from "@ethers-v6";

describe("AuthenticationStorage", () => {
  const reverter = new Reverter();

  let SECOND: SignerWithAddress;

  let secondIdentity: Identity;

  let erc721: ERC721Mock;
  let tree: PoseidonSMT;
  let authStorage: AuthenticationStorage;

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

    const Proxy: ERC1967Proxy__factory = await ethers.getContractFactory("ERC1967Proxy");

    let proxy = await Proxy.deploy(await tree.getAddress(), "0x");
    tree = tree.attach(await proxy.getAddress()) as PoseidonSMT;

    const VerifiableCommitmentVerifier = await ethers.getContractFactory("VerifiableCommitmentVerifier");
    const verifier = await VerifiableCommitmentVerifier.deploy();

    proxy = await Proxy.deploy(await authStorage.getAddress(), "0x");
    authStorage = authStorage.attach(await proxy.getAddress()) as AuthenticationStorage;

    await tree.__PoseidonSMT_init(await authStorage.getAddress(), 80);
    await authStorage.__AuthenticationStorage_init(await tree.getAddress(), await verifier.getAddress());

    const ERC721Factory = await ethers.getContractFactory("ERC721Mock");
    erc721 = await ERC721Factory.deploy("ERC721", "ERC721");

    await erc721.mint(SECOND.address, 1);
    secondIdentity = new Identity(ethers.id(SECOND.address));

    await time.increase(SECONDS_IN_MONTH * 12);

    await reverter.snapshot();
  });

  afterEach(reverter.revert);

  describe("#register", () => {
    it("should register with valid proof correctly", async () => {
      const circuit = await zkit.getCircuit("VerifiableCommitment");

      const timestamp = (await time.latest()) - 2;
      const deadline = timestamp + 1;

      const data = await circuit.generateProof({
        contractId: await erc721.getAddress(),
        nftId: 1,
        nftOwner: SECOND.address,
        deadline: deadline,
        babyJubJubPK_Ax: secondIdentity.PK.p[0],
        babyJubJubPK_Ay: secondIdentity.PK.p[1],
        timestamp,
      });

      const proof = normalizeProof(data);

      await expect(
        authStorage.register(
          await erc721.getAddress(),
          1,
          SECOND.address,
          ethers.toBeHex(data.publicSignals[0], 32),
          deadline,
          proof,
        ),
      )
        .to.emit(authStorage, "Registered")
        .withArgs(await erc721.getAddress(), 1, SECOND.address, ethers.toBeHex(data.publicSignals[0], 32), deadline);
    });
  });
});
