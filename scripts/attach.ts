import { ethers } from "hardhat";
import { SplitVerifier } from "../typechain-types";

const attach = async () => {
  const ZKDemo = await ethers.getContractFactory("ZKDemo");
  const zkDemo = ZKDemo.attach("0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0");

  console.log(`Attached to ${zkDemo.address}`);
  return zkDemo;
};

async function main() {
  const zkDemo = await attach();
  await zkDemo.createNote("0xce1b3f82c8944134c83fd1bd1525bd9fb24b450f0a563931ed2dfbd024ff6a72", "0x44265540c3437d1178c0acfddf0813fe36b9176982c636f8dd782b172aad5db7")
  const proof: SplitVerifier.ProofStruct = {
    a: {
      X: "0x03685b27faf479fbca6a3cc7ccd14dc8e18647f036b9bd75667284a8c2205b75",
      Y: "0x0b4990e12ca1cf22b485f9a185ec2e2955454b5dc8442f9e6929acabf5e5a9bb",
    },
    b: {
      X: [
        "0x00c323250051b7c99807afaf8e7c086d2853a3e84864d97bc155f4e9c6357f5b",
        "0x09978c5e2000b4ce967b39914fa16820afe66bd1712b2dc9fab26a6269c5181a"
      ],
      Y: [
        "0x293332475f0ff8bf351bc93e168723e36d451895b5b25b20987d0310f6b21aa6",
        "0x10f594d0bdd1d756173109fc95020d9419ef2086b32e2395ca3873dcec638f18"
      ],
    },
    c: {
      X: "0x026d8208560da5324eed9c48c159428fc35c604cd4b1749b37e90def595f12a8",
      Y: "0x1fe43bc6648ba850042398d45422604ba4149724467dc6f9aa107ec3b561820b",
    },
  };
  const nullifier = ethers.BigNumber.from(
    "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
  );
  type BN = typeof nullifier;
  const mixed_note_ids: [BN, BN, BN] =
    [
      ethers.BigNumber.from(
        "0xce1b3f82c8944134c83fd1bd1525bd9fb24b450f0a563931ed2dfbd024ff6a72"
      ),
      ethers.BigNumber.from("0"),
      ethers.BigNumber.from("0"),
    ];
  const mixed_amts: [BN, BN, BN] =
  [
    ethers.BigNumber.from(
      "0x44265540c3437d1178c0acfddf0813fe36b9176982c636f8dd782b172aad5db7"
    ),
    ethers.BigNumber.from("0"),
    ethers.BigNumber.from("0"),
  ];
  const new_note_ids: [BN, BN] = [
    ethers.BigNumber.from(
      "0x37027392efbd1c3f1e0d12d8dd2028986521f03c4816774eb45c3af653bae3d8"
    ),
    ethers.BigNumber.from(
      "0xf7ae27748230ac48433baf1a57810205ba0408bd07eeeb5962f2a01814e88223"
    ),
  ];
  const new_amts: [BN, BN] = [
    ethers.BigNumber.from(
      "0x5eb7f6b433a40409b0f0c43218ecf3405b9e5fbb2edfe72e097492267c3a3726"
    ),
    ethers.BigNumber.from(
      "0x58cc17ad2b673c58198b9c16420192bd4db3828d3856fedf3857ddc965bfb933"
    ),
  ];
  await zkDemo.splitNotes(proof, nullifier, mixed_note_ids, mixed_amts, new_note_ids, new_amts);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
