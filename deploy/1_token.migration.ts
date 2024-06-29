import { Deployer, Reporter } from "@solarity/hardhat-migrate";

import { ERC721Mock__factory } from "@ethers-v6";

export = async (deployer: Deployer) => {
  const erc721Mock = await deployer.deploy(ERC721Mock__factory, ["Mock NFT", "Mock NFT"]);

  Reporter.reportContracts(["ERC721Mock", await erc721Mock.getAddress()]);
};
