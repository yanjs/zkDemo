// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./Verifier.sol";

contract ZKDemo is Verifier {
    mapping(uint => bool) public notes;
    // true for existence, false (default) for non-existence.
    mapping(uint => bool) public nullifier;
    // true for existence, false (default) for non-existence.

    constructor() {}

    function createNote(uint noteId) public {
        require(!notes[noteId], "note exists");
        notes[noteId] = true;
    }

    function transferNote() public {

    }
}
