import { ethers } from "hardhat";

const deploy = async () => {
  const ZKDemo = await ethers.getContractFactory("ZKDemo");
  const zkDemo = await ZKDemo.deploy();
  await zkDemo.deployed();

  console.log(`Deployed to ${zkDemo.address}`);
  return zkDemo;
}

async function main() {
  const zkDemo = await deploy();
  await zkDemo.createNote(ethers.BigNumber.from(
    "0xbf387d2095b532863cef8117d583eafbe9f8e2bbc92ae710c6efa7d329e00bce"));
  console.log("note created");
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
