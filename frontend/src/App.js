import "./App.css";
import Note from "./Note";
import { ethers } from "ethers";
import detectEthereumProvider from "@metamask/detect-provider";
import { useEffect, useState } from "react";
import sha256 from "crypto-js/sha256";
import {
  hash,
  add,
  calcAllKeys,
  encrypt,
  toUint256Hex,
  getMergeCmds,
  getSplitCmds,
} from "./zokratesUtils";
import abi from "./ZKDemoAbi";

const zkDemoAddr = "0xad1f98ca30953d3DB8B0FbDc80b749BcE7572e9f";

function App() {
  const getMetaMaskProvider = () => {
    return detectEthereumProvider()
      .then((p) => {
        if (p && p.isMetaMask) {
          return p;
        }
        return Promise.reject("Please install MetaMask!");
      })
      .then((p) => {
        return new ethers.providers.Web3Provider(p);
      })
      .then((p) => {
        return p
          .send("wallet_switchEthereumChain", [{ chainId: "0x5" }])
          .then((_) => p)
          .catch((_) => Promise.reject("Only support goerli testnet"));
      })
      .then((p) =>
        p
          .send("eth_requestAccounts", [])
          .then((_) => p)
          .catch((e) =>
            Promise.reject(`Failed to retrieve wallet, because "${e.message}"`)
          )
      );
  };

  const [zkDemo, setZKDemo] = useState(null);
  const [provider, setProvider] = useState(null);
  const [address, setAddress] = useState(null);
  const [mainSecret, setMainSecret] = useState("");
  const [nextNonce, setNextNonce] = useState(0);
  const [myNotes, setMyNotes] = useState([]);

  const handleCreateNote = (e) => {
    e.preventDefault();
    const amt = parseInt(e.target["amt"].value);
    const keys = calcAllKeys(mainSecret, nextNonce);
    zkDemo
      .createNote(
        "0x" + keys.noteId,
        "0x" + encrypt(toUint256Hex(amt), keys.encKey)
      )
      .then(() => {
        console.log("Success");
      })
      .catch((e) => {
        console.log("ERROR ", e);
      });
  };

  const handleMerge = (e) => {
    e.preventDefault();
    const n1 = parseInt(e.target["n1"].value);
    const n2 = parseInt(e.target["n2"].value);
    const amt1 = myNotes[n1].amt;
    const amt2 = myNotes[n2].amt;
    const n1Keys = calcAllKeys(mainSecret, n1);
    const n2Keys = calcAllKeys(mainSecret, n2);
    const nextKeys = calcAllKeys(mainSecret, nextNonce);
    const proofJSON = e.target["proof"].value;
    if (proofJSON === "") {
      const cmd = getMergeCmds(
        [n1Keys.nullifier, n2Keys.nullifier],
        [n1Keys.noteId, n2Keys.noteId, toUint256Hex(0)],
        [
          encrypt(amt1, n1Keys.encKey),
          encrypt(amt2, n2Keys.encKey),
          toUint256Hex(0),
        ],
        nextKeys.noteId,
        encrypt(add(amt1, amt2), nextKeys.encKey),
        [n1Keys.secret, n2Keys.secret],
        [n1Keys.noteId, n2Keys.noteId],
        [amt1, amt2],
        nextKeys.encKey
      );
      document.getElementById("commandsHint").innerText = cmd;
    } else {
      const proofObject = JSON.parse(proofJSON);
      const proof = {
        a: {
          X: proofObject.proof.a[0],
          Y: proofObject.proof.a[1],
        },
        b: {
          X: proofObject.proof.b[0],
          Y: proofObject.proof.b[1],
        },
        c: {
          X: proofObject.proof.c[0],
          Y: proofObject.proof.c[1],
        },
      };
      zkDemo
        .mergeNotes(
          proof,
          ["0x" + n1Keys.nullifier, "0x" + n2Keys.nullifier],
          ["0x" + n1Keys.noteId, "0x" + n2Keys.noteId, "0x" + toUint256Hex(0)],
          [
            "0x" + encrypt(amt1, n1Keys.encKey),
            "0x" + encrypt(amt2, n2Keys.encKey),
            "0x" + toUint256Hex(0),
          ],
          "0x" + nextKeys.noteId,
          "0x" + encrypt(add(amt1, amt2), nextKeys.encKey)
        )
        .then(() => {
          console.log("Success");
        })
        .catch((e) => {
          console.log("Error ", e);
        });
    }
  };

  const handleSplit = (e) => {
    e.preventDefault();
    const n1 = parseInt(e.target["n1"].value);
    let destEncKey = e.target["k1"].value;
    const amt = parseInt(e.target["amt"].value);
    const n1Keys = calcAllKeys(mainSecret, n1);
    let nextKeys = calcAllKeys(mainSecret, nextNonce);

    if (destEncKey === nextKeys.encKey) {
      nextKeys = calcAllKeys(mainSecret, nextNonce + 1);
    }

    const srcAmt = Number("0x" + myNotes[n1].amt);
    const proofJSON = e.target["proof"].value;
    if (proofJSON === "") {
      const cmd = getSplitCmds(
        n1Keys.nullifier,
        [n1Keys.noteId, toUint256Hex(0), toUint256Hex(0)],
        [
          encrypt(toUint256Hex(srcAmt), n1Keys.encKey),
          toUint256Hex(0),
          toUint256Hex(0),
        ],
        [nextKeys.noteId, hash(destEncKey + toUint256Hex(0))],
        [
          encrypt(toUint256Hex(srcAmt - amt), nextKeys.encKey),
          encrypt(toUint256Hex(amt), destEncKey),
        ],
        n1Keys.secret,
        n1Keys.noteId,
        [nextKeys.encKey, destEncKey],
        [toUint256Hex(srcAmt - amt), toUint256Hex(amt)]
      );
      document.getElementById("commandsHint").innerText = cmd;
    } else {
      const proofObject = JSON.parse(proofJSON);
      const proof = {
        a: {
          X: proofObject.proof.a[0],
          Y: proofObject.proof.a[1],
        },
        b: {
          X: proofObject.proof.b[0],
          Y: proofObject.proof.b[1],
        },
        c: {
          X: proofObject.proof.c[0],
          Y: proofObject.proof.c[1],
        },
      };
      zkDemo
        .splitNotes(
          proof,
          "0x" + n1Keys.nullifier,
          [
            "0x" + n1Keys.noteId,
            "0x" + toUint256Hex(0),
            "0x" + toUint256Hex(0),
          ],
          [
            "0x" + encrypt(toUint256Hex(srcAmt), n1Keys.encKey),
            "0x" + toUint256Hex(0),
            "0x" + toUint256Hex(0),
          ],
          ["0x" + nextKeys.noteId, "0x" + hash(destEncKey + toUint256Hex(0))],
          [
            "0x" + encrypt(toUint256Hex(srcAmt - amt), nextKeys.encKey),
            "0x" + encrypt(toUint256Hex(amt), destEncKey),
          ]
        )
        .then(() => {
          console.log("Success");
        })
        .catch((e) => {
          console.log("Error ", e);
        });

    }
  };

  useEffect(() => {
    getMetaMaskProvider().then((p) => {
      setProvider(p);
      const s = p.getSigner();
      setZKDemo(new ethers.Contract(zkDemoAddr, abi.abi, s));
    });
  }, []);

  useEffect(() => {
    provider?.listAccounts().then((d) => {
      const cutAddr = d[0].substring(2);
      setAddress(cutAddr);

      // MainSecret should be calculated from the private key,
      // but we can't get the private key.
      const hashAddr = hash(cutAddr);
      const hashAddr2 = hash(hashAddr + hashAddr);

      setMainSecret(sha256(d[0]).toString());
    });
  }, [provider]);

  useEffect(() => {
    if (mainSecret === "") return;
    const queryMyNotes = async () => {
      let currNonce = 0;
      let notes = [];
      while (true) {
        const keys = calcAllKeys(mainSecret, currNonce);
        const value = await zkDemo?.notes("0x" + keys.noteId);
        const valueStr = value.toHexString().substring(2);
        if (value.eq("0x0")) break;
        const isUsed = await zkDemo?.nullifiers("0x" + keys.nullifier);
        console.log(currNonce, keys.noteId, value, valueStr, isUsed);
        notes.push({
          noteId: keys.noteId,
          nonce: currNonce,
          amt: encrypt(valueStr, keys.encKey),
          isUsed,
        });
        currNonce += 1;
      }
      setNextNonce(currNonce);
      setMyNotes(notes);
    };
    if (zkDemo) {
      setTimeout(queryMyNotes, 500);
    }
  }, [zkDemo, mainSecret]);

  return (
    <div className="App">
      <div>Hello, {address}</div>
      <div>Your main secret is
        <input value={mainSecret}></input>
      </div>
      <div>Your next nonce is {nextNonce}</div>
      <div>
        Your next encKey is{" "}
        {mainSecret ? calcAllKeys(mainSecret, nextNonce).encKey : null}
      </div>
      <div>
        Your next noteId is{" "}
        {mainSecret ? calcAllKeys(mainSecret, nextNonce).noteId : null}
      </div>
      <form className="border gap" onSubmit={handleCreateNote}>
        <div>Create Note (Free except Gas Fee)</div>
        <input placeholder="amount" type="number" name="amt" />
        <br />
        <input type="submit" />
      </form>
      <div className="border gap">
        <div>Your Notes</div>
        {myNotes.map((v) => {
          return (
            <Note
              nonce={v.nonce}
              noteId={v.noteId}
              amt={v.amt}
              isUsed={v.isUsed}
              key={v.nonce}
            />
          );
        })}
      </div>
      <form className="border gap" onSubmit={handleMerge}>
        <div>Merge Two Notes</div>
        <input placeholder="source note nonce 1" type="input" name="n1" />
        <br />
        <input placeholder="source note nonce 2" type="input" name="n2" />
        <br />
        <input type="submit" />
        <textarea placeholder="proof" name="proof" />
      </form>
      <form className="border gap" onSubmit={handleSplit}>
        <div>Transfer</div>
        <input placeholder="source note nonce" type="input" name="n1" />
        <br />
        <input placeholder="amount" type="number" name="amt" />
        <br />
        <input placeholder="destination encKey" type="input" name="k1" />
        <br />
        <input type="submit" />
        <textarea placeholder="proof" name="proof" />
      </form>
      <div className="border gap">
        <div>Commands to Run</div>
        <div className="gap">
          <tt id="commandsHint">...</tt>
        </div>
      </div>
    </div>
  );
}

export default App;
