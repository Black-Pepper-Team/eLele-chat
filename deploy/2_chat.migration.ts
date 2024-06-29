import { Deployer, Reporter } from "@solarity/hardhat-migrate";

import {
  AuthenticationStorage__factory,
  Chat__factory,
  ERC1967Proxy__factory,
  PoseidonSMT__factory,
  PostMessageVerifier__factory,
  VerifiableCommitmentVerifier__factory,
} from "@ethers-v6";

import { deployPoseidons } from "@/deploy/helpers";

export = async (deployer: Deployer) => {
  await deployPoseidons(deployer, [1, 2, 3]);

  const verifiableCommitmentVerifier = await deployer.deploy(VerifiableCommitmentVerifier__factory);
  const postMessageVerifier = await deployer.deploy(PostMessageVerifier__factory);

  let authStorage = await deployer.deploy(AuthenticationStorage__factory);
  let tree = await deployer.deploy(PoseidonSMT__factory);
  let chat = await deployer.deploy(Chat__factory);

  await deployer.deploy(ERC1967Proxy__factory, [await authStorage.getAddress(), "0x"], {
    name: "AuthenticationStorage Proxy",
  });
  authStorage = await deployer.deployed(AuthenticationStorage__factory, "AuthenticationStorage Proxy");

  await deployer.deploy(ERC1967Proxy__factory, [await tree.getAddress(), "0x"], {
    name: "PoseidonSMT Proxy",
  });
  tree = await deployer.deployed(PoseidonSMT__factory, "PoseidonSMT Proxy");

  await deployer.deploy(ERC1967Proxy__factory, [await chat.getAddress(), "0x"], {
    name: "Chat Proxy",
  });
  chat = await deployer.deployed(Chat__factory, "Chat Proxy");

  await tree.__PoseidonSMT_init(await authStorage.getAddress(), 80);
  await authStorage.__AuthenticationStorage_init(
    await tree.getAddress(),
    await verifiableCommitmentVerifier.getAddress(),
  );
  await chat.__Chat_init(await tree.getAddress(), await postMessageVerifier.getAddress());

  Reporter.reportContracts(
    ["AuthenticationStorage", await authStorage.getAddress()],
    ["PoseidonSMT", await tree.getAddress()],
    ["Chat", await chat.getAddress()],
  );
};
