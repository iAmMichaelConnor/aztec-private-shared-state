// Derived from TaceoLabs/monty-hall-aztec (MIT; the root NOTICE).
//
// Follows the SAFE API [https://eprint.iacr.org/2023/522.pdf](https://eprint.iacr.org/2023/522.pdf)
pub struct AE {}

// `encrypt` / `decrypt` take any length N with a multi-block duplex of rate 3:
// after each full block of 3 fields the state is permuted, and the tag is
// permutation(state)[0] after the last block. The machine's Rust side
// (sidecar-core `ae`) computes the same state transitions; testvectors/ae.json
// pins both.

// The IO-pattern tag in the capacity element. Words: absorb 2
// (0x80000002), then per block squeeze k and absorb k (k, 0x80000000 | k), then
// squeeze 1; followed by the domain separator 0x4142. Up to two blocks (N <= 6,
// 208 bits) the words are packed big-endian into one field, 32 bits each (one
// block of N = 1: 0x800000020000000180000001000000014142); from
// three blocks they would not fit, so the tag is the Poseidon2 hash of the words
// and the separator, one field each. Changing this changes every ciphertext the
// machine seals (state records, INPUT_SHARED envelopes); both sides must move
// together.
global DOMAIN_SEPARATOR: Field = 0x4142;
global ABSORB: Field = 0x80000000;
global RATE: u32 = 3;
global MAX_PACKED_BLOCKS: u32 = 2;
global TWO_POW_16: Field = 0x10000;
global TWO_POW_32: Field = 0x100000000;
global TWO_POW_64: Field = 0x10000000000000000;

impl AE {
    // Word `w` of the IO pattern for N fields (without the domain separator).
    fn pattern_word<let N: u32>(w: u32) -> Field {
        let blocks = (N + RATE - 1) / RATE;
        if w == 0 {
            ABSORB + 2
        } else if w == 2 * blocks + 1 {
            1
        } else {
            let b = (w - 1) / 2;
            let left = N - RATE * b;
            let k = if left < RATE { left } else { RATE };
            if (w - 1) % 2 == 0 {
                k as Field
            } else {
                ABSORB + k as Field
            }
        }
    }

    // The capacity element of the initial state for N plaintext fields.
    pub fn pattern_tag<let N: u32>() -> Field {
        let blocks = (N + RATE - 1) / RATE;
        let words = 2 * blocks + 2;
        if blocks <= MAX_PACKED_BLOCKS {
            let mut packed = 0;
            for w in 0..words {
                packed = packed * TWO_POW_32 + AE::pattern_word::<N>(w);
            }
            packed * TWO_POW_16 + DOMAIN_SEPARATOR
        } else {
            // poseidon2_hash([words..., DOMAIN_SEPARATOR]): the sponge of
            // protocol_types::hash::poseidon2_hash (IV = length << 64, rate 3), written out
            // because the length is not a type-level constant.
            let len = words + 1;
            let mut state = [0, 0, 0, (len as Field) * TWO_POW_64];
            let mut lane = 0;
            for i in 0..len {
                let value = if i == words {
                    DOMAIN_SEPARATOR
                } else {
                    AE::pattern_word::<N>(i)
                };
                state[lane] += value;
                lane += 1;
                if lane == RATE {
                    state = std::hash::poseidon2_permutation(state);
                    lane = 0;
                }
            }
            if lane != 0 {
                state = std::hash::poseidon2_permutation(state);
            }
            state[0]
        }
    }

    // Returns ciphertext and tag. N must be at least 1.
    pub fn encrypt<let N: u32>(data: [Field; N], key: Field, nonce: Field) -> ([Field; N], Field) {
        std::static_assert(N > 0, "ae: N must be at least 1");
        let mut state = std::hash::poseidon2_permutation([key, nonce, 0, AE::pattern_tag::<N>()]);
        let mut ciphertext = [0; N];
        for i in 0..N {
            if (i != 0) & (i % RATE == 0) {
                state = std::hash::poseidon2_permutation(state);
            }
            state[i % RATE] += data[i];
            ciphertext[i] = state[i % RATE];
        }
        let tag = std::hash::poseidon2_permutation(state)[0];
        (ciphertext, tag)
    }

    // Returns the plaintext; fails on a tag mismatch. N must be at least 1.
    pub fn decrypt<let N: u32>(
        ciphertext: [Field; N],
        tag: Field,
        key: Field,
        nonce: Field,
    ) -> [Field; N] {
        let (plaintext, ok) = AE::open(ciphertext, tag, key, nonce);
        assert(ok, "ae: tag mismatch");
        plaintext
    }

    // Returns the plaintext and whether the tag matches, for a reader that
    // tries more than one nonce. N must be at least 1.
    pub fn open<let N: u32>(
        ciphertext: [Field; N],
        tag: Field,
        key: Field,
        nonce: Field,
    ) -> ([Field; N], bool) {
        std::static_assert(N > 0, "ae: N must be at least 1");
        let mut state = std::hash::poseidon2_permutation([key, nonce, 0, AE::pattern_tag::<N>()]);
        let mut plaintext = [0; N];
        for i in 0..N {
            if (i != 0) & (i % RATE == 0) {
                state = std::hash::poseidon2_permutation(state);
            }
            plaintext[i] = ciphertext[i] - state[i % RATE];
            state[i % RATE] = ciphertext[i];
        }
        let tag2 = std::hash::poseidon2_permutation(state)[0];
        (plaintext, tag == tag2)
    }
}

#[test]
fn encrypt_decrypt_round_trip() {
    let (c1, t1) = AE::encrypt([0x123], 0x456, 0x789);
    assert_eq(AE::decrypt(c1, t1, 0x456, 0x789), [0x123]);
    let (c3, t3) = AE::encrypt([0x123, 0x456, 0x789], 0xabc, 0xdef);
    assert_eq(AE::decrypt(c3, t3, 0xabc, 0xdef), [0x123, 0x456, 0x789]);
}

#[test(should_fail_with = "ae: tag mismatch")]
fn decrypt_wrong_nonce_fails() {
    let (ciphertext, tag) = AE::encrypt([0x123], 0x456, 0x789);
    let _ = AE::decrypt(ciphertext, tag, 0x456, 0x78a);
}

#[test(should_fail_with = "ae: tag mismatch")]
fn decrypt_wrong_key_fails() {
    let (ciphertext, tag) = AE::encrypt([0x123], 0x456, 0x789);
    let _ = AE::decrypt(ciphertext, tag, 0x457, 0x789);
}

#[test(should_fail_with = "ae: tag mismatch")]
fn decrypt_tampered_tag_fails() {
    let (ciphertext, tag) = AE::encrypt([0x123], 0x456, 0x789);
    let _ = AE::decrypt(ciphertext, tag + 1, 0x456, 0x789);
}

#[test(should_fail_with = "ae: tag mismatch")]
fn decrypt_single_slot_tamper_fails() {
    let (mut ct, tag) = AE::encrypt([0x123, 0x456, 0x789], 0xabc, 0xdef);
    ct[2] += 1; // tamper only the third slot
    let _ = AE::decrypt(ct, tag, 0xabc, 0xdef);
}

// The hashed pattern tag (N >= 7) is the poseidon2 hash of the words.
#[test]
fn hashed_pattern_tag_is_poseidon2_of_the_words() {
    let words = [ABSORB + 2, 3, ABSORB + 3, 3, ABSORB + 3, 1, ABSORB + 1, 1, DOMAIN_SEPARATOR];
    assert_eq(AE::pattern_tag::<7>(), protocol_types::hash::poseidon2_hash(words));
}

// KAT: the vectors of testvectors/ae.json pin the SAFE-sponge encoding
// (domain-separation tags, absorb/squeeze order); any change to the sponge
// wiring must turn them red.
// BEGIN written by scripts/gen-noir-vectors.py from testvectors/ae.json
#[test]
fn kat_encrypt_n1() {
    let key = 0x0000000000000000000000000000000000000000000000000000000000000456;
    let nonce = 0x0000000000000000000000000000000000000000000000000000000000000789;
    let plaintext: [Field; 1] = [
        0x0000000000000000000000000000000000000000000000000000000000000123,
    ];
    let expected: [Field; 1] = [
        0x286c1a243c558666b5831713c826988e93d25672dccc21d787e88c81c78209b9,
    ];
    let (ciphertext, tag) = AE::encrypt(plaintext, key, nonce);
    assert_eq(
        AE::pattern_tag::<1>(),
        0x0000000000000000000000000000800000020000000180000001000000014142,
    );
    assert_eq(ciphertext, expected);
    assert_eq(tag, 0x143e77b81535095f93e3a50e6fbc2debc978878f97c60407a07c839736d98df4);
    assert_eq(AE::decrypt(ciphertext, tag, key, nonce), plaintext);
}

#[test]
fn kat_encrypt_n2() {
    let key = 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383;
    let nonce = 0x10188a1adb8e4fa209f257bb8da16800bd6f5158b1333edc91727f69dea8e7c2;
    let plaintext: [Field; 2] = [
        0x2c4d14bb62c38cd0f20ea2b5eea34ced70e361a7b6721bb00b4bda691413b6a8,
        0x1934241c60b9c9a6f96581fff641a59ff616c8825ba19a7b0d1bddd986e2c55f,
    ];
    let expected: [Field; 2] = [
        0x136bbd14b407670dbae4cba218555a845b3ef513c30f7b46abee5cdba457072c,
        0x29e2b59448eeec69458e52f820794f9ea4404278f0da9e87f6140ad899f2e5c8,
    ];
    let (ciphertext, tag) = AE::encrypt(plaintext, key, nonce);
    assert_eq(
        AE::pattern_tag::<2>(),
        0x0000000000000000000000000000800000020000000280000002000000014142,
    );
    assert_eq(ciphertext, expected);
    assert_eq(tag, 0x10698ad5d1f3435a9c8c00613a613b7e7654e046f8b252f2178f422e126a571a);
    assert_eq(AE::decrypt(ciphertext, tag, key, nonce), plaintext);
}

#[test]
fn kat_encrypt_n3() {
    let key = 0x11e37b81ef869f8ef9f0ffde8e5850d0680802913fbd9884a114fd28a0b58b0f;
    let nonce = 0x2bc00d90b885b09d12764e764410f7f693f514f7f3ca14d916741ff3968b3079;
    let plaintext: [Field; 3] = [
        0x22a3326bea716451064f50a0a5f3bb75174f119b74f25b2784b936905b1f186d,
        0x18ff110fac007ab061c17af9b831d12aabc3b0024fc240be77b0ed4823495531,
        0x23c6e7433be821b7ed8614271106bc88a98f3bf09c030dec29fd75bb5434fd8b,
    ];
    let expected: [Field; 3] = [
        0x2875f12d28ef55af7a2b2fdee98813aebd07bfe54eee979f14ac8a72f9b1fc0d,
        0x0e900d591dd5f2b35766262d9238c077148234a8213847d1dcf597788327e7e4,
        0x2995edf1a948e5e447f0dfa9244610e3e2c8f9a0a51fcf0f95744ee5d3dd29e4,
    ];
    let (ciphertext, tag) = AE::encrypt(plaintext, key, nonce);
    assert_eq(
        AE::pattern_tag::<3>(),
        0x0000000000000000000000000000800000020000000380000003000000014142,
    );
    assert_eq(ciphertext, expected);
    assert_eq(tag, 0x0aed363617295849dc5f5ad2cb906ccdedca3d095ca4f0280e50d8d088dd1b4f);
    assert_eq(AE::decrypt(ciphertext, tag, key, nonce), plaintext);
}

#[test]
fn kat_encrypt_n4() {
    let key = 0x041e146f5552de77ae83f63d3a2d08da303a65bcc4b89250816ac6798e58178d;
    let nonce = 0x0ee3ab17c1b73bcadf0d7edac246e599d8022ecf5f05111e9221bb2960913052;
    let plaintext: [Field; 4] = [
        0x1efed0ee79e22ed36984e298f6e4e870a2f4b3aa782b68c7b7d9f70896fa8715,
        0x1a830b4593ce8586b685c24774298833baaf3b0dde9b66f38322183b9d0cf539,
        0x27773df558787b8e347052e3e06348f52ddfd114c35c499d35c1e76bc59339d0,
        0x0407eab8beda5e61a8bdffeddaa75801a77247f4ad0c571b5a2a22d073322773,
    ];
    let expected: [Field; 4] = [
        0x0eb9f2eb8bfd1f46c29f5d6a3aabc4f09bfd82adec1ee79837438618c6305b0a,
        0x1c8f0e1fcc4cf8c0c6951de703e4494d0069eb3d98eae0ef4c3296b35ad1fa3f,
        0x1b0b9f17110245305f3b1e0445e5838124536c1353ec3db2503e7e10ee0ea0f6,
        0x1700dd42ea3d0724c2e465d12415e6bb9f2616cb7d4afaf313335a3d040e065d,
    ];
    let (ciphertext, tag) = AE::encrypt(plaintext, key, nonce);
    assert_eq(
        AE::pattern_tag::<4>(),
        0x0000000000008000000200000003800000030000000180000001000000014142,
    );
    assert_eq(ciphertext, expected);
    assert_eq(tag, 0x2901cc7aef50849ec5fe72dee3d3dd872971110e6a3f9151cc7e9bb5674b0c88);
    assert_eq(AE::decrypt(ciphertext, tag, key, nonce), plaintext);
}

#[test]
fn kat_encrypt_n7() {
    let key = 0x06544259956caa5c3dbeadc24ab9db966c4ebcd79d02a34543be54b9b0922e3b;
    let nonce = 0x2c937f1591069f176b99513624fb7904bee82e84a87dec4affd34723906f4eb9;
    let plaintext: [Field; 7] = [
        0x269efec1d2f971f10e867460115ac6486a462d4cbb186e7eb9687c1b7571f2a7,
        0x0463a7a8adbe2a153b7b569f1bfa0eb25f2030a741b91c93c78821360a475bd5,
        0x26a9f6746bb3f4728df3ccc600cc11a4d07a85d028129084dd9405fac17d9412,
        0x22dfb339bf093ca887e71d44dac3eacae532a7b01e56f279ab53c9bc61b1f40e,
        0x0b9e4eee7c7f0e575bd76291c83b457c699c12d5149728f7a30eba94b32620ce,
        0x17f51921e89d2a4a2f24b1132c662c01c8bb6ca97423b4f25a867cb5c3d58263,
        0x040c367bfeb7372ac0a9133a6168ac1ff169664569c218b3073312ec345efa7e,
    ];
    let expected: [Field; 7] = [
        0x1ec99ddd30ce35e71005edf11f8bf3421349feaeeecda2812da90abc9775b4a6,
        0x2ff7a50928c4dd4656abcde3f2506f52d7f079f0ab6265c03ebdb6edd621292a,
        0x0f0bb9e4f0a0f8e8b21149b7db9c8593a3956090ca3cd279641ebde645999d72,
        0x1f3055e276bd6d97953c96a642b497ff76c17507f6eeddbbed55443b3d6d1952,
        0x2b773c9d123ed710c32e6d4246be91d84b93c0d18b8b47955df496656d509f46,
        0x04a404fca16b2606f43a14040e152d0fce035c88a71c83ebf16e9c451dac0f43,
        0x243aac144741bcccf69271f653795f105a5cc40c15c678546671cdd3860d5dd4,
    ];
    let (ciphertext, tag) = AE::encrypt(plaintext, key, nonce);
    assert_eq(
        AE::pattern_tag::<7>(),
        0x15bf4bf91478aa08bbc4213f384c637acda8338f1a765f7e2fd1803371a42089,
    );
    assert_eq(ciphertext, expected);
    assert_eq(tag, 0x2a917c61f3f6fda529a929cd6e6efd3b3bc325167246c51b1965823326b5a9bc);
    assert_eq(AE::decrypt(ciphertext, tag, key, nonce), plaintext);
}

#[test]
fn kat_encrypt_n10() {
    let key = 0x0d1d43fdc97c9ef267ae7e323a2a9ef979d4126f87cfe76c3b3df404751de148;
    let nonce = 0x125a01f4719849183e4e0c4f0a89f776ad07fcbfac75b417757258e7f8fa14c0;
    let plaintext: [Field; 10] = [
        0x2fa6ff2561f2db877cf28d9b594219af4a7b8361f407d7bd7d2e8ebccb00cb9d,
        0x18a1ec0172e2eff7062082e393bd7ea5e55b17ff7aecfd2f71ffa85e2f85d656,
        0x2296345efcb0b3526a8b2ee421193ab901a987b5c899faacd4659fcdfb25b27c,
        0x16d1e619586e8a48568674f9245143ef2a1a81d29277f873e9bc0ed2e4651d90,
        0x24807d73cbd05a86f63f942600fcebe9448df32b91a4df3345c2cfe304a9e8ea,
        0x26f1020ceb28e904706dc7423dc32fe012015a65f3b1e1a703b218c0a0d884c7,
        0x2971ac8ff9b69ed109404bcaade3bc7374c351052c3ecee50b89500906f94d06,
        0x0435753a6f8c8efe17e7684568e42819f16d87e54661708419c21039805f66d4,
        0x27e4e6133652f24b7c466f82adba4076b3bfe4024b7a3c2f2b4a4a1bf5bd1cc4,
        0x02ff8aca1d2ea1f2bbcc2a076e5ed7ee883b07ecb069fcdb49f2a5f9355d821c,
    ];
    let expected: [Field; 10] = [
        0x14e4af4745bbb462d4f64226be949a8f06a104911842d8c54d39b41cc7370bec,
        0x1e8bfd67e4e25151580ed659db25be1fdf30e8c189601a680724a08494522916,
        0x1e156edb7e5083b7e0759a11454fc40c74e7022c199b2dfe8017a7f63438c8a6,
        0x017e3142c94b4aaaed61f4c51a61f361cf03382bc17c4422bcf30aa6c8a6088b,
        0x1972af88e089d1d9ab4ff1fdb9b4e6e339b0a19d83f671c20282d1b3580ba30f,
        0x1d6486b2317e6ad882dbf7f39f99f3ea885d8fe1e9747d4be9c9c804d202f38e,
        0x06b239260ab38358f43f23ebce52d76e8225eee251e6a93c1c0421d2a522df64,
        0x25ff2503f9734730502434f80d93d9d4db513bed871f45c65854312048ffae62,
        0x283ee72b71c7643d08a2c15a6cbd7159c8bbddfc5c01b44a88cf33d1c3df9089,
        0x100bfe99d14c47b3b5a90e5aafcfb7affb62786fd5af5271ebcc12a24938da3d,
    ];
    let (ciphertext, tag) = AE::encrypt(plaintext, key, nonce);
    assert_eq(
        AE::pattern_tag::<10>(),
        0x25b36da0262d343d040c438e2c4d7ad163569d413cd4de89b81e14d0a4caa914,
    );
    assert_eq(ciphertext, expected);
    assert_eq(tag, 0x16e0bc186d67b9273711197d15e33f0c6628d13565147ed211f21bc2a04d30c0);
    assert_eq(AE::decrypt(ciphertext, tag, key, nonce), plaintext);
}
// END written by scripts/gen-noir-vectors.py

#[test(should_fail_with = "ae: tag mismatch")]
fn decrypt_multi_block_tamper_fails() {
    let (mut ct, tag) = AE::encrypt([1, 2, 3, 4, 5, 6, 7], 0x456, 0x789);
    ct[6] += 1; // tamper only the last block
    let _ = AE::decrypt(ct, tag, 0x456, 0x789);
}

#[test(should_fail_with = "ae: tag mismatch")]
fn decrypt_multi_block_wrong_nonce_fails() {
    let (ct, tag) = AE::encrypt([1, 2, 3, 4], 0x456, 0x789);
    let _ = AE::decrypt(ct, tag, 0x456, 0x78a);
}
