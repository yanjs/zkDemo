
const importSha = `
import "hashes/sha256/512bitPadded" as sha256;
`;

const addSource = `
def add(\
    u32[8] a,\
    u32[8] b\
) -> u32[8] {
    u32 mut carry = 0;
    u32[8] mut res = [0,0,0,0,0,0,0,0];
    for u32 idx in 0..8 {
        u32 i = 7 - idx;
        u32 temp = a[i] + b[i];
        res[i] = temp + carry;
        carry = if temp < a[i] || temp < b[i] {
            1
        } else {
            if carry == 1 && res[i] == 0 {
                1
            } else {
                0
            }
        };
    }
    // No overflow allowed
    assert(carry == 0);

    return res;
}
`;

const cmpSource = `
// return -1 if a < b, 0 if a == b, 1 if a > b
def cmp(\
    u32[8] a,\
    u32[8] b\
) -> u32 {
    u32 mut res = 0;
    bool mut locked = false;
    for u32 i in 0..8 {
        res = if locked {
            res
        } else {
            if a[i] < b[i] {
                -1
            } else {
                if a[i] > b[i] {
                    1
                } else {
                    0
                }
            }
        };
        locked = if locked {
            locked
        } else {
            if a[i] != b[i] {
                true
            } else {
                false
            }
        };
    }

    return res;
}
`;

const configSource = `
const u32 N_MIX = 3;
`;

const containsSource = configSource + `
def contains(\
    u32[N_MIX][8] set,\
    u32[8] elem\
) -> bool {
    // assert set contains elem
    bool mut any_found = false;
    for u32 i in 0..N_MIX {
        any_found = if elem == set[i] {
            true
        } else { any_found };
    }
    return any_found;
}
`;

const splitSource = importSha + addSource + cmpSource + containsSource + `
const u32 N_SPLIT = 2;

def main(\
    u32[8] nullifier, /* input */ \
    u32[N_MIX][8] mixed_note_ids, /* input */ \
    u32[N_SPLIT][8] new_note_ids, /* output */ \
    private u32[8] secret, /* input */ \
    private u32[8] note_id, /* input */ \
    private u32[N_SPLIT][8] new_note_ls, /* output */ \
    private u32[N_SPLIT][8] amts /* output */ \
) {
    u32[8] zero = [0;8];
    u32[8] one = [0,0,0,0,0,0,0,1];
    // assert amt > 0
    for u32 i in 0..N_SPLIT {
        assert(cmp(amts[i], zero) != 0);
    }

    // assert note_id in mixed_note_ids
    assert(contains(mixed_note_ids, note_id));

    // assert note_id == sha256(secret, amt)
    u32[8] mut sum = [0;8];
    for u32 i in 0..N_SPLIT {
        sum = add(sum, amts[i]);
    }
    u32[8] exp_note_l = sha256(secret, one);
    u32[8] exp_note_id = sha256(exp_note_l, sum);
    assert(exp_note_id == note_id);

    // assert nullifier == sha256(secret, 0)
    u32[8] exp_nullifier = sha256(secret, zero);
    assert(exp_nullifier == nullifier);

    // assert new_note_ids = sha256(new_note_ls, amt)
    for u32 i in 0..N_SPLIT {
        u32[8] exp_new_note_id = sha256(new_note_ls[i], amts[i]);
        assert(exp_new_note_id == new_note_ids[i]);
    }

    return;
}`;

const mergeSource = importSha + addSource + cmpSource + containsSource + `
const u32 N_MERGE = 2;

def main(\
    u32[N_MERGE][8] nullifiers, /* input */ \
    u32[N_MIX][8] mixed_note_ids, /* input */ \
    u32[8] new_note_id, /* output */ \
    private u32[N_MERGE][8] secrets, /* input */ \
    private u32[N_MERGE][8] note_ids, /* input */ \
    private u32[N_MERGE][8] amts, /* input */ \
    private u32[8] new_note_l /* output */ \
) {
    u32[8] zero = [0;8];
    u32[8] one = [0,0,0,0,0,0,0,1];
    // assert amt > 0
    for u32 i in 0..N_MERGE {
        assert(cmp(amts[i], zero) != 0);
    }

    // assert note_id in mixed_note_ids
    for u32 i in 0..N_MERGE {
        assert(contains(mixed_note_ids, note_ids[i]));
    }

    // assert note_id == sha256(secret, amt)
    for u32 i in 0..N_MERGE {
        u32[8] exp_note_l = sha256(secrets[i], one);
        u32[8] exp_note_id = sha256(exp_note_l, amts[i]);
        assert(exp_note_id == note_ids[i]);
    }

    // assert sum(...) = new amt
    u32[8] mut sum = [0;8];
    for u32 i in 0..N_MERGE {
        sum = add(sum, amts[i]);
    }

    // assert nullifier == sha256(secret, 0)
    for u32 i in 0..N_MERGE {
        u32[8] exp_note_nullifier = sha256(secrets[i], zero);
        assert(exp_note_nullifier == nullifiers[i]);
    }

    // assert new_note_id = sha256(new_note_l, amt)
    u32[8] exp_new_note_id = sha256(new_note_l, sum);
    assert(new_note_id == exp_new_note_id);

    return;
}
`;

export {addSource, cmpSource, configSource, containsSource, mergeSource, splitSource};