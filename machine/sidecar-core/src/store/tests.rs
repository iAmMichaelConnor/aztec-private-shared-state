//! The store's unit tests: the vector encoding, the test keys, and the suite on the
//! in-memory backend.

pub(crate) use super::testing::{id, new_request, ns, round, shared};
use super::*;

#[test]
fn the_stored_vector_encoding() {
    let vec = vec![Elem::Public(Fr::from(5u64)), shared(9)];
    let bytes = encode_vec(&vec);
    assert_eq!(bytes.len(), 1 + 32 + 1 + 64);
    assert_eq!(bytes[0], 0);
    assert_eq!(bytes[1], 5); // little-endian
    assert_eq!(bytes[33], 1);
    assert_eq!(bytes[34], 9);
    assert_eq!(bytes[66], 10);
    assert_eq!(decode_vec(&bytes).unwrap(), vec);
    assert!(decode_vec(&[2]).is_err());
    assert!(decode_vec(&[1, 0, 0]).is_err());
}

#[test]
fn the_test_keys_are_the_sample_deployment_s() {
    let (a, b) = (testing::node_keys(), crate::keys::tests::sample_keys(0));
    assert_eq!(a.enc_pk(), b.enc_pk());
    assert_eq!(a.sig_pk(), b.sig_pk());
}

#[test]
fn the_store_suite_on_memory_store() {
    assert_eq!(
        testing::suite(MemoryStore::new),
        testing::cases_without_values::<MemoryStore>().len()
            + testing::cases_with_values::<MemoryStore>().len()
    );
}
