# Sample Hardhat Project

This project demonstrates a basic Hardhat use case. It comes with a sample contract, a test for that contract, and a script that deploys that contract.

Try running some of the following tasks:

```shell
npx hardhat help
npx hardhat test
REPORT_GAS=true npx hardhat test
npx hardhat node
npx hardhat run scripts/deploy.ts
```
# zkDemo

## setup environment

```sh
docker run -ti zokrates/zokrates /bin/bash
```

```
zokrates compile -i Split.zok -o Split.out -s Split.abi.json
zokrates setup -i Split.out -p Split.proving.key -v Split.verification.key
zokrates export-verifier -i Split.verification.key -o SplitVerifier.sol
```

```
zokrates compile -i Merge.zok -o Merge.out -s Merge.abi.json
zokrates setup -i Merge.out -p Merge.proving.key -v Merge.verification.key
zokrates export-verifier -i Merge.verification.key -o MergeVerifier.sol
```

## complete proof

```
zokrates compute-witness -i Merge.out -s Merge.abi.json -o Merge.witness -a
```