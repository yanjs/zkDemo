// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {MergeVerifier} from "./MergeVerifier.sol";
import {SplitVerifier} from "./SplitVerifier.sol";

contract ZKDemo {
    uint public constant N_MIX = 3;
    uint public constant N_MERGE = 2;
    uint public constant N_SPLIT = 2;
    mapping(uint => bool) public notes;
    // true for existence, false (default) for non-existence.
    mapping(uint => bool) public nullifiers;
    // true for existence, false (default) for non-existence.

    event CreateNote(uint indexed noteId);
    event UseNullifier(uint indexed nullifierId);

    constructor() {
        notes[0] = true;
    }

    // For debug purposes, these functions are public
    function createNote(uint noteId) public {
        require(!notes[noteId], "note exists");
        notes[noteId] = true;
        emit CreateNote(noteId);
    }

    function useNullifier(uint nullifier) public {
        require(!nullifiers[nullifier], "nullifier exists");
        nullifiers[nullifier] = true;
        emit UseNullifier(nullifier);
    }

    function getNthUint32(uint num, uint i) public pure returns (uint) {
        return (num >> (256 - 32 - i * 32)) & 0xFFFFFFFF;
    }

    function mergeNotes(
        MergeVerifier.Proof memory proof,
        uint[N_MERGE] memory _nullifiers,
        uint[N_MIX] memory mixed_note_ids,
        uint new_note_id
    ) public {
        // Check existence of notes and nullifiers
        for (uint i = 0; i < N_MERGE; i++) {
            require(!nullifiers[_nullifiers[i]], "nullifier is used");
        }
        for (uint i = 0; i < N_MIX; i++) {
            require(notes[mixed_note_ids[i]], "note should exist");
        }
        require(notes[new_note_id], "new note should not exist");

        // Fill input parameters
        uint[48] memory input;
        for (uint j = 0; j < N_MERGE; j++) {
            uint ofs = j * 8;
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] =
                    getNthUint32(_nullifiers[j], i);
            }
        }
        for (uint j = 0; j < N_MIX; j++) {
            uint ofs = j * 8 + N_MERGE * 8;
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] =
                    getNthUint32(mixed_note_ids[j], i);
            }
        }
        for (uint i = 0; i < 8; i++) {
            input[N_MERGE * 8 + N_MIX * 8 + i] =
                getNthUint32(new_note_id, i);
        }

        // zk proof
        MergeVerifier mv = new MergeVerifier();
        require(mv.verifyTx(proof, input), "zk proof failed");

        // write to blockchain
        for (uint i = 0; i < N_MERGE; i++) {
            useNullifier(_nullifiers[i]);
        }
        createNote(new_note_id);
    }

    function splitNotes(
        SplitVerifier.Proof memory proof,
        uint nullifier,
        uint[N_MIX] memory mixed_note_ids,
        uint[N_SPLIT] memory new_note_ids
    ) public {
        // Check existence of notes and nullifiers
        require(!nullifiers[nullifier], "nullifier is used");
        for (uint i = 0; i < N_MIX; i++) {
            require(notes[mixed_note_ids[i]], "note should exist");
        }
        for (uint i = 0; i < N_SPLIT; i++) {
            require(!notes[new_note_ids[i]], "note should not exist");
        }

        // Fill input parameters
        uint[48] memory input;
        for (uint i = 0; i < 8; i++) {
            input[i] =
                getNthUint32(nullifier, i);
        }
        for (uint j = 0; j < N_MIX; j++) {
            uint ofs = j * 8 + 8;
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] =
                    getNthUint32(mixed_note_ids[j], i);
            }
        }
        for (uint j = 0; j < N_SPLIT; j++) {
            uint ofs = j * 8 + 8 + 8 * N_MIX;
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] =
                    getNthUint32(new_note_ids[j], i);
            }
        }

        // zk proof
        SplitVerifier mv = new SplitVerifier();
        require(mv.verifyTx(proof, input), "zk proof failed");

        // write to blockchain
        useNullifier(nullifier);
        for (uint i = 0; i < N_SPLIT; i++) {
            createNote(new_note_ids[i]);
        }
    }
}
