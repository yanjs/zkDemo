// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {MergeVerifier} from "./MergeVerifier.sol";
import {SplitVerifier} from "./SplitVerifier.sol";

contract ZKDemo {
    uint public constant N_MIX = 3;
    uint public constant N_MERGE = 2;
    uint public constant N_SPLIT = 2;
    // notes to encrypted amount
    mapping(uint => uint) public notes;
    // true for existence, false (default) for non-existence.
    mapping(uint => bool) public nullifiers;
    MergeVerifier public mv;
    SplitVerifier public sv;

    event CreateNote(uint indexed noteId);
    event UseNullifier(uint indexed nullifierId);

    constructor(MergeVerifier _mv, SplitVerifier _sv) {
        notes[0] = 1;
        mv = _mv;
        sv = _sv;
    }

    // For debug purposes, these functions are public
    function createNote(uint noteId, uint enc_amt) public {
        require(notes[noteId] == 0, "note exists");
        notes[noteId] = enc_amt;
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
        uint[N_MIX] memory mixed_enc_amts,
        uint new_note_id,
        uint enc_amt
    ) public {
        // Check existence of notes and nullifiers
        for (uint i = 0; i < N_MERGE; i++) {
            require(!nullifiers[_nullifiers[i]], "nullifier is used");
        }
        require(notes[new_note_id] == 0, "new note should not exist");
        for (uint i = 0; i < N_MIX; i++) {
            require(
                mixed_note_ids[i] == 0 ||
                    notes[mixed_note_ids[i]] == mixed_enc_amts[i],
                "The amount of this note is not correct"
            );
        }

        // Fill input parameters
        uint[80] memory input;
        uint ofs = 0;
        for (uint j = 0; j < N_MERGE; j++) {
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] = getNthUint32(_nullifiers[j], i);
            }
            ofs += 8;
        }
        for (uint j = 0; j < N_MIX; j++) {
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] = getNthUint32(mixed_note_ids[j], i);
            }
            ofs += 8;
        }
        for (uint j = 0; j < N_MIX; j++) {
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] = getNthUint32(mixed_enc_amts[j], i);
            }
            ofs += 8;
        }
        for (uint i = 0; i < 8; i++) {
            input[ofs + i] = getNthUint32(new_note_id, i);
        }
        ofs += 8;
        for (uint i = 0; i < 8; i++) {
            input[ofs + i] = getNthUint32(enc_amt, i);
        }
        ofs += 8;
        require(ofs == 80, "This contract is corrupted");

        // zk proof
        require(mv.verifyTx(proof, input), "zk proof failed");

        // write to blockchain
        for (uint i = 0; i < N_MERGE; i++) {
            useNullifier(_nullifiers[i]);
        }
        createNote(new_note_id, enc_amt);
    }

    function splitNotes(
        SplitVerifier.Proof memory proof,
        uint nullifier,
        uint[N_MIX] memory mixed_note_ids,
        uint[N_MIX] memory mixed_enc_amts,
        uint[N_SPLIT] memory new_note_ids,
        uint[N_SPLIT] memory new_enc_amts
    ) public {
        // Check existence of notes and nullifiers
        require(!nullifiers[nullifier], "nullifier is used");
        for (uint i = 0; i < N_MIX; i++) {
            require(
                mixed_note_ids[i] == 0 || notes[mixed_note_ids[i]] > 0,
                "note should exist"
            );
        }
        for (uint i = 0; i < N_SPLIT; i++) {
            require(notes[new_note_ids[i]] == 0, "note should not exist");
        }
        for (uint i = 0; i < N_MIX; i++) {
            require(
                mixed_note_ids[i] == 0 ||
                    notes[mixed_note_ids[i]] == mixed_enc_amts[i],
                "The amount of this note is not correct"
            );
        }

        // Fill input parameters
        uint[88] memory input;
        uint ofs = 0;
        for (uint i = 0; i < 8; i++) {
            input[i] = getNthUint32(nullifier, i);
        }
        ofs += 8;
        for (uint j = 0; j < N_MIX; j++) {
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] = getNthUint32(mixed_note_ids[j], i);
            }
            ofs += 8;
        }
        for (uint j = 0; j < N_MIX; j++) {
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] = getNthUint32(mixed_enc_amts[j], i);
            }
            ofs += 8;
        }
        for (uint j = 0; j < N_SPLIT; j++) {
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] = getNthUint32(new_note_ids[j], i);
            }
            ofs += 8;
        }
        for (uint j = 0; j < N_SPLIT; j++) {
            for (uint i = 0; i < 8; i++) {
                input[ofs + i] = getNthUint32(new_enc_amts[j], i);
            }
            ofs += 8;
        }
        require(ofs == 88, "This contract is corrupted");

        // zk proof
        require(sv.verifyTx(proof, input), "zk proof failed");

        // write to blockchain
        useNullifier(nullifier);
        for (uint i = 0; i < N_SPLIT; i++) {
            createNote(new_note_ids[i], new_enc_amts[i]);
        }
    }
}
