import { PrivateKey, PublicKey, Signature } from "@iden3/js-crypto";

import { toLittleEndian } from "@iden3/js-iden3-core";

export class Identity {
  public sk: PrivateKey;
  public PK: PublicKey;

  constructor(pk: string) {
    const [key, publicKey] = Identity.ExtractPubXY(pk);

    this.sk = key;
    this.PK = publicKey;
  }

  public signHash(hash: bigint): Signature {
    return this.sk.signPoseidon(hash);
  }

  public static ExtractPubXY(privateKHex: string): [PrivateKey, PublicKey] {
    if (privateKHex[1] !== "x") {
      privateKHex = "0x" + privateKHex;
    }

    const pk = new PrivateKey(Identity.bigIntToUint8Array(BigInt(privateKHex)));

    return [pk, pk.public()];
  }

  public static bigIntToUint8Array(bigintValue: bigint, outputByteSize = 32) {
    return toLittleEndian(bigintValue, outputByteSize);
  }
}
