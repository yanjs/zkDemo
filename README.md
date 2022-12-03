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


### setup web ui (optional)

```sh
cd frontend
npm install
npm start
```

### setup zokrates environment (docker shell)

```sh
docker run -v ./zk_latest:/home/zo -ti zokrates/zokrates /bin/bash
cd /home/zo
```

#### Run the following only once

Inside container shell
```
zokrates compile -i Split.zok -o Split.out -s Split.abi.json
zokrates compile -i Merge.zok -o Merge.out -s Merge.abi.json
```
