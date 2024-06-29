import { ethers } from "hardhat";
import { BaseContract } from "ethers";

import { ProofStruct } from "@solarity/zkit";

// @ts-ignore
import { poseidonContract } from "circomlibjs";
import { VerifierHelper } from "@/generated-types/ethers/contracts/AuthenticationStorage";

export async function getPoseidon(num: number): Promise<BaseContract> {
  if (num < 1 || num > 6) {
    throw new Error("Poseidon Hash: Invalid number");
  }

  const [deployer] = await ethers.getSigners();
  const PoseidonHasher = new ethers.ContractFactory(
    poseidonContract.generateABI(num),
    poseidonContract.createCode(num),
    deployer,
  );
  const poseidonHasher = await PoseidonHasher.deploy();
  await poseidonHasher.waitForDeployment();

  return poseidonHasher;
}

export function normalizeProof(data: ProofStruct): VerifierHelper.ProofPointsStruct {
  swap(data.proof.pi_b[0], 0, 1);
  swap(data.proof.pi_b[1], 0, 1);

  return {
    a: data.proof.pi_a.slice(0, 2).map((x: any) => padElement(BigInt(x))) as any,
    b: data.proof.pi_b.slice(0, 2).map((x: any[]) => x.map((y: any) => padElement(BigInt(y)))) as any,
    c: data.proof.pi_c.slice(0, 2).map((x: any) => padElement(BigInt(x))) as any,
  };
}

export function swap(arr: any, i: number, j: number) {
  const temp = arr[i];
  arr[i] = arr[j];
  arr[j] = temp;
}

export function padElement(element: any) {
  return ethers.toBeHex(element, 32);
}
