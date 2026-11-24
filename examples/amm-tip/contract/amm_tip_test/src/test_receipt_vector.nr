//! The node's receipt route on this example's receipt-intake manifest
//! (testvectors/receipt_route.json, written by sidecar-tip
//! `write_receipt_vectors`): the three receipts the machine's signer made
//! over the app inputs [amount_in, direction, min_out, partial_note] verify
//! here, under the request id and inputs hash the library computes for
//! `swap_with_receipts`. vk_hash and user_nonce are the manifest's reserved
//! operands, not app inputs; the partial note (`$partial_note`) is an app
//! input named by its parameter, and no requester enters, so the node
//! hashes exactly the list this contract does. sidecar-tip's test of the
//! vector checks that every value below is the committed one.
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::FromField;
use pss_public_contract::{chain_request_id, check_receipts, inputs_hash, Receipt, receipt_message};
use pss_tip_test::nodes::NODE_SIG_PK;

global NAMESPACE: Field = 0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809;
global VK_HASH: Field = 0x2a8f1c0e9b7d6a5f4e3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6;
global USER_NONCE: Field = 0x2a2a2a;
// a swap of 5000 in direction 1 with a minimum output of 4000 into the
// partial note 0x5eed
global INPUTS: [Field; 4] = [5000, 1, 4000, 0x5eed];
global EXPIRY_BLOCK: u32 = 1300;
global INPUTS_HASH: Field = 0x0494f8cb1a0f4d8bc0ac795dd40cb75efcc804593def9d71544fd3b37940fb9d;
global REQUEST_ID: Field = 0x01f1018f78cab8243db90fd5f51c92e295ab1d61c3b4ff72732baf806adb4742;

fn route_receipts() -> [Receipt; 3] {
    [
        Receipt {
            s: [
                0x000000000000000000000000000000000ea57f753438f16ef65dc2e3b3bdc1ca,
                0x000000000000000000000000000000001aa1d06c0ae031bdabf28ec2c0bd43e1,
            ],
            e: [
                0x000000000000000000000000000000009a19c16cd38c067bb31ff3f1c6f7a2b5,
                0x0000000000000000000000000000000007d0faa2308330707251d3924b7570bd,
            ],
        },
        Receipt {
            s: [
                0x000000000000000000000000000000004e6b6b06b250ab263830c2f6b2eea17f,
                0x000000000000000000000000000000002ab4bb1ac6d8c2acec945b7332d05d97,
            ],
            e: [
                0x0000000000000000000000000000000053cd4b8362cd2f72d6125160aa6c597f,
                0x00000000000000000000000000000000083c5b958006d2b0a6d1b6eda0a16131,
            ],
        },
        Receipt {
            s: [
                0x000000000000000000000000000000009480b1366d503c3ebedb519f7d5f8377,
                0x000000000000000000000000000000001522b8d6a99deee3eebe1ec7d115efeb,
            ],
            e: [
                0x000000000000000000000000000000006c560e391669122540c138f7643c6e31,
                0x000000000000000000000000000000000843ee07a3652714f1b6b99220bd25cc,
            ],
        },
    ]
}

// The contract's request functions hash the swap inputs and then the
// partial note (amm_tip `PLAIN_SWAP_INPUTS`), the list the route hashes.
#[test]
fn the_route_hashes_the_app_inputs_as_the_intake_does() {
    assert_eq(INPUTS.len(), amm_tip::app::PLAIN_SWAP_INPUTS);
    assert_eq(inputs_hash(INPUTS), INPUTS_HASH);
    let id = chain_request_id(AztecAddress::from_field(NAMESPACE), VK_HASH, inputs_hash(INPUTS), USER_NONCE);
    assert_eq(id, REQUEST_ID);
}

#[test]
unconstrained fn the_routes_three_receipts_verify_in_circuit() {
    check_receipts(
        NODE_SIG_PK,
        route_receipts(),
        receipt_message(REQUEST_ID, INPUTS_HASH, EXPIRY_BLOCK),
    );
}

// The same receipts under an inputs hash that also counts vk_hash and
// user_nonce as app inputs do not verify.
#[test(should_fail_with = "invalid receipt from node 0")]
unconstrained fn receipts_under_another_inputs_hash_are_refused() {
    let wrong = inputs_hash([VK_HASH, INPUTS[0], INPUTS[1], INPUTS[2], INPUTS[3], USER_NONCE]);
    check_receipts(
        NODE_SIG_PK,
        route_receipts(),
        receipt_message(REQUEST_ID, wrong, EXPIRY_BLOCK),
    );
}
