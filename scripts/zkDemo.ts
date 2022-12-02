import {ethers} from "hardhat";
import crypto from "crypto";
import { initialize } from "zokrates-js";
import { addSource, mergeSource, splitSource } from "./source";

const zero = ethers.BigNumber.from("0");

type BN = typeof zero;

const sha256 = (data: Buffer): Buffer =>
    crypto.createHash('sha256').update(data).digest();

class note {
    secret: BN;
    amt: BN;
    constructor(secret: BN, amt: BN) {
        this.secret = secret;
        this.amt = amt;
    }
}

initialize().then((zokratesProvider) => {
    // compilation
    const mergeArtifacts = zokratesProvider.compile(mergeSource);
    //const splitArtifacts = zokratesProvider.compile(splitSource);

    return;

    // computation
    const { witness, output } = zokratesProvider.computeWitness(artifacts, ["2"]);

    // run setup
    const keypair = zokratesProvider.setup(artifacts.program);

    // generate proof
    const proof = zokratesProvider.generateProof(artifacts.program, witness, keypair.pk);

    // export solidity verifier
    const verifier = zokratesProvider.exportSolidityVerifier(keypair.vk);
    
    // or verify off-chain
    const isVerified = zokratesProvider.verify(keypair.vk, proof);
    console.log(isVerified);
    return;
})