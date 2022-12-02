import { ethers } from "hardhat";

const deploy = async () => {
  const MV = await ethers.getContractFactory("MergeVerifier");
  const SV = await ethers.getContractFactory("SplitVerifier");
  const ZKDemo = await ethers.getContractFactory("ZKDemo");
  const mv = await MV.deploy();
  const sv = await SV.deploy();
  const zkDemo = await ZKDemo.deploy(
    mv.address,
    sv.address,
  );
  await zkDemo.deployed();

  console.log(`Deployed to ${zkDemo.address}`);
  return zkDemo;
};

async function main() {
  const zkDemo = await deploy();
  console.log("contract deployed");
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
