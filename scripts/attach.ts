import { ethers } from "hardhat";
import { SplitVerifier } from "../typechain-types";
import { initialize } from "zokrates-js";
import crypto from "crypto";

const attach = async () => {
  const ZKDemo = await ethers.getContractFactory("ZKDemo");
  const zkDemo = ZKDemo.attach("0x5fbdb2315678afecb367f032d93f642f64180aa3");

  console.log(`Attached to ${zkDemo.address}`);
  return zkDemo;
};

async function main() {
  const zkDemo = await attach();
  const proof: SplitVerifier.ProofStruct = {
    a: {
      X: "0x2bdd901fea0faafcf085d617c2594691ed14c1d9f85af3ebdf2215b3eee3dd8f",
      Y: "0x05337c3cb4647d061dfa80afb94adc0f338f5eb2dbb4c477d451400d594a6208",
    },
    b: {
      X: [
        "0x162146b2f77f7fad3b3a3ef032fa3d0e551d5534afd0c5c30339e8ca767353a4",
        "0x20c9a7e9692f22957b87254282e62c9b9b8c25ab2fe5bd2060e42c425cd3a468"
      ],
      Y: [
        "0x005020d82e3e39f3ff3093f8218c501d362df76fcbbe7a7988ddcfdbd3181419",
        "0x2290142f4b5a3446279cfac13b179513e9df3f196117c7d5cf08cda60496700e"
      ],
    },
    c: {
      X: "0x17cb2631b3377ee6af16de0f84b7a94eba8151685bad3fd86e06697ecb930c70",
      Y: "0x28bcdc7c592af44a5871b6429a7cee50c0be504460b4f843187d4f4e774a4b00",
    },
  };
  const nullifier = ethers.BigNumber.from(
    "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
  );
  type BN = typeof nullifier;
  const mixed_note_ids: [BN, BN, BN] =
    [
      ethers.BigNumber.from(
        "0xbf387d2095b532863cef8117d583eafbe9f8e2bbc92ae710c6efa7d329e00bce"
      ),
      ethers.BigNumber.from("0"),
      ethers.BigNumber.from("0"),
    ];
  const new_note_ids: [BN, BN] = [
    ethers.BigNumber.from(
      "0x6c3627b97827dd35a91f9953746dee5790709eca44399333e1252a48921385cc"
    ),
    ethers.BigNumber.from(
      "0x1ea6e37432e1b08fdc88b369f44cc140f87fbf8e09b84366a1e7fb33d7c11ca5"
    ),
  ];
  await zkDemo.splitNotes(proof, nullifier, mixed_note_ids, new_note_ids);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
