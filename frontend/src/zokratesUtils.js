import sha256 from "crypto-js/sha256";
import CryptoJS from "crypto-js";
import { Buffer } from "buffer";
import { ethers } from "ethers";

const swap32 = (val) => {
  return (
    ((val & 0xff) << 24) |
    ((val & 0xff00) << 8) |
    ((val >> 8) & 0xff00) |
    ((val >> 24) & 0xff)
  );
};

const add = (x, y) => {
  const xb = ethers.BigNumber.from("0x" + x);
  const yb = ethers.BigNumber.from("0x" + y);
  return xb.add(yb).toHexString().substring(2);
};

const toUint256Hex = (num) => {
  const hexStr = num.toString(16);
  const padNZeros = 8 - (hexStr.length % 8);
  const paddedHex = "0".repeat(padNZeros + 64) + hexStr;
  return paddedHex.slice(-64);
};

const hexToUint32ArrayString = (hexStr) => {
  const padNZeros = 8 - (hexStr.length % 8);
  hexStr = "0".repeat(padNZeros + 64) + hexStr;
  const buf = Buffer.from(hexStr, "hex");
  const bufuint32 = new Uint32Array(buf.buffer);
  const bufuint32be = bufuint32.map(swap32);
  const bufuint32arr = Array.from(bufuint32be);
  const padded = [0, 0, 0, 0, 0, 0, 0, 0].concat(bufuint32arr).slice(-8);
  return padded.toString().replace(/,/g, " ") + " ";
};

const zero = hexToUint32ArrayString("0");
const one = hexToUint32ArrayString("1");

const hash = (hexStr) => {
  const datab = CryptoJS.enc.Hex.parse(hexStr);
  return sha256(datab).toString(CryptoJS.enc.Hex);
};

const calcAllKeys = (mainSecret, nonce) => {
  const secret = hash(mainSecret + nonce);
  const nullifier = hash(secret + toUint256Hex(0));
  const encKey = hash(secret + toUint256Hex(1));
  const noteId = hash(encKey + toUint256Hex(0));

  return {
    secret,
    nullifier,
    encKey,
    noteId,
  };
};

const encrypt = (value, key) => {
  const vb = Buffer.from(value, "hex");
  const kb = Buffer.from(key, "hex");
  const res = vb.map((b, i) => b ^ kb[i]);
  return ("0".repeat(64) + res.toString("hex")).slice(-64);
};

const getMergeCmds = (
  nullifiers,
  mixedNoteIds,
  mixedEncAmts,
  newNoteId,
  encAmt,
  secrets,
  noteIds,
  amts,
  encKey
) => {
  let str =
    "zokrates compute-witness -i Merge.out -s Merge.abi.json -o Merge.witness -a ";
  for (let n of nullifiers) {
    str += hexToUint32ArrayString(n) + " ";
  }
  for (let n of mixedNoteIds) {
    str += hexToUint32ArrayString(n) + " ";
  }
  for (let n of mixedEncAmts) {
    str += hexToUint32ArrayString(n) + " ";
  }
  str += hexToUint32ArrayString(newNoteId) + " ";
  str += hexToUint32ArrayString(encAmt) + " ";
  for (let n of secrets) {
    str += hexToUint32ArrayString(n) + " ";
  }
  for (let n of noteIds) {
    str += hexToUint32ArrayString(n) + " ";
  }
  for (let n of amts) {
    str += hexToUint32ArrayString(n) + " ";
  }
  str += hexToUint32ArrayString(encKey) + " ";
  return (
    str +
    " && zokrates generate-proof -i Merge.out -j Merge.proof.json -p Merge.proving.key -w Merge.witness\n\n"
  );
};

const getSplitCmds = (
  nullifier,
  mixedNoteIds,
  mixedEncAmts,
  newNoteIds,
  newAmts,
  secret,
  noteId,
  encKeys,
  amts
) => {
  let str =
    "zokrates compute-witness -i Split.out -s Split.abi.json -o Split.witness -a ";

  str += hexToUint32ArrayString(nullifier) + " ";
  for (let n of mixedNoteIds) {
    str += hexToUint32ArrayString(n) + " ";
  }
  for (let n of mixedEncAmts) {
    str += hexToUint32ArrayString(n) + " ";
  }
  for (let n of newNoteIds) {
    str += hexToUint32ArrayString(n) + " ";
  }
  for (let n of newAmts) {
    str += hexToUint32ArrayString(n) + " ";
  }
  str += hexToUint32ArrayString(secret) + " ";
  str += hexToUint32ArrayString(noteId) + " ";
  for (let n of encKeys) {
    str += hexToUint32ArrayString(n) + " ";
  }
  for (let n of amts) {
    str += hexToUint32ArrayString(n) + " ";
  }
  return (
    str +
    " && zokrates generate-proof -i Split.out -j Split.proof.json -p Split.proving.key -w Split.witness\n\n"
  );
};

export {
  hexToUint32ArrayString,
  hash,
  toUint256Hex,
  add,
  zero,
  one,
  calcAllKeys,
  encrypt,
  getMergeCmds,
  getSplitCmds,
};
