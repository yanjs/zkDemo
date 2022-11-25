// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./verifier.sol";
import "./daiiToken.sol";
import "hardhat/console.sol";


contract SecretNote is Verifier {
    
  daiiToken public DAI_TOKEN_ADDRESS = new daiiToken();
  constructor() {}

  enum State {Invalid, Created, Spent}
  mapping(bytes32 => State) public notes; // mapping of hash of the note to state
  string[] public allNotes;
  bytes32[] public allHashedNotes;

  function createNote(address owner, uint amount, string memory encryptedNote) public {
    bytes32 note = sha256(abi.encodePacked(abi.encodePacked(bytes32(uint(uint160(address(owner))))),abi.encodePacked(bytes32(uint(uint160(amount))))));
    createNote(note, encryptedNote);
  }

  function claimNote(uint amount) public {
    bytes32 note = sha256(abi.encodePacked(abi.encodePacked(bytes32(uint(uint160(address(msg.sender))))), abi.encodePacked(bytes32(uint(uint160(amount))))));
    require(
      notes[note] == State.Created,
      'note doesnt exist'
    );
    notes[note] = State.Spent;
    require(
      DAI_TOKEN_ADDRESS.transfer(msg.sender, amount * (10 ** 18)),
      'daiToken transfer failed'
    );
    emit Claim(msg.sender, amount * (10 ** 18));
  }
  event Claim(address to, uint amount);

  function transferNote(
    uint[2] memory a,
    uint[2] memory a_p,
    uint[2][2] memory b,
    uint[2] memory b_p,
    uint[2] memory c,
    uint[2] memory c_p,
    uint[2] memory h,
    uint[2] memory k,
    uint[7] memory input,
    string memory encryptedNote1,
    string memory encryptedNote2
  ) public {
    require(
      verifyTx(a, a_p, b, b_p, c, c_p, h, k, input),
      'Invalid zk proof'
    );

    bytes32 spendingNote = calcNoteHash(input[0], input[1]);
    require(
      notes[spendingNote] == State.Created,
      'spendingNote doesnt exist'
    );

    notes[spendingNote] = State.Spent;
    bytes32 newNote1 = calcNoteHash(input[2], input[3]);
    createNote(newNote1, encryptedNote1);
    bytes32 newNote2 = calcNoteHash(input[4], input[5]);
    createNote(newNote2, encryptedNote2);
  }

  function getNotesLength() public view returns(uint) {
    return allNotes.length;
  }

  event NoteCreated(bytes32 noteId, uint index);
  function createNote(bytes32 note, string memory encryptedNote) internal {
    notes[note] = State.Created;
    allNotes.push(encryptedNote);
    allHashedNotes.push(note);
    emit NoteCreated(note, allNotes.length - 1);
  }

  function calcNoteHash(uint _a, uint _b) internal returns(bytes32 note) {
    bytes16 a = bytes16(uint128(_a));
    bytes16 b = bytes16(uint128(_b));
    bytes memory _note = new bytes(32);
    
    for (uint i = 0; i < 16; i++) {
      _note[i] = a[i];
      _note[16 + i] = b[i];
    }
    note = bytesToBytes32(_note, 0);
  }

  function bytesToBytes32(bytes memory b, uint offset) internal returns(bytes32 out) {
    bytes32 out;
    for (uint i = 0; i < 32; i++) {
      out |= bytes32(b[offset + i] & 0xFF) >> (i * 8);
    }
    return out;
  }
}