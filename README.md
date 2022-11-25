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

```
secret // secret
amount // secret
note_l := hash(secret, 1) // medium secret
note_id := hash(note_l, amount) // public
nullifier := hash(secret, 0)
```