//! Test running well-formed inner WASM txs via finalize block handler.

#![no_main]

use arbitrary::Arbitrary;
use data_encoding::HEXUPPER;
use libfuzzer_sys::fuzz_target;
use namada_apps_lib::wallet;
use namada_core::key::PublicKeyTmRawHash;
use namada_node::shell;
use namada_node::shell::test_utils::TestShell;
use namada_node::shims::abcipp_shim_types::shim::request::{
    FinalizeBlock, ProcessedTx,
};
use namada_node::shims::abcipp_shim_types::shim::response::TxResult;
use namada_node::shims::abcipp_shim_types::shim::TxBytes;
use namada_sdk::address::Address;
use namada_sdk::governance::{InitProposalData, VoteProposalData};
use namada_sdk::key::common;
use namada_sdk::token::{self, DenominatedAmount};
use namada_sdk::tx::Tx;
use namada_sdk::{account, address, storage, tx};
use namada_tx::data::pos::BecomeValidator;

static mut SHELL: Option<TestShell> = None;

#[allow(clippy::large_enum_variant)]
#[derive(Arbitrary, Debug)]
enum TxKind {
    InitAccount(account::InitAccount),
    BecomeValidator(BecomeValidator),
    UnjailValidator(Address),
    DeactivateValidator(Address),
    ReactivateValidator(Address),
    InitProposal(InitProposalData),
    VoteProposal(VoteProposalData),
    RevealPk(common::PublicKey),
    UpdateAccount(account::UpdateAccount),
    Transfer(token::Transfer),
}

fuzz_target!(|kinds: Vec<TxKind>| run(kinds));

fn run(kinds: Vec<TxKind>) {
    let shell = unsafe {
        match SHELL.as_mut() {
            Some(shell) => shell,
            None => {
                let (shell, _recv, _, _) = shell::test_utils::setup();
                SHELL = Some(shell);
                SHELL.as_mut().unwrap()
            }
        }
    };

    // Construct the txs
    let mut txs_bytes: Vec<TxBytes> = Vec::with_capacity(kinds.len());
    let signer = wallet::defaults::albert_keypair();
    for kind in kinds {
        let mut tx = Tx::from_type(tx::data::TxType::Raw);

        use TxKind::*;
        let code_tag = match kind {
            InitAccount(data) => {
                tx.add_data(data);
                tx::TX_INIT_ACCOUNT_WASM
            }
            BecomeValidator(data) => {
                tx.add_data(data);
                tx::TX_BECOME_VALIDATOR_WASM
            }
            UnjailValidator(data) => {
                tx.add_data(data);
                tx::TX_UNJAIL_VALIDATOR_WASM
            }
            DeactivateValidator(data) => {
                tx.add_data(data);
                tx::TX_DEACTIVATE_VALIDATOR_WASM
            }
            ReactivateValidator(data) => {
                tx.add_data(data);
                tx::TX_REACTIVATE_VALIDATOR_WASM
            }
            InitProposal(data) => {
                tx.add_data(data);
                tx::TX_INIT_PROPOSAL
            }
            VoteProposal(data) => {
                tx.add_data(data);
                tx::TX_VOTE_PROPOSAL
            }
            RevealPk(data) => {
                tx.add_data(data);
                tx::TX_REVEAL_PK
            }
            UpdateAccount(data) => {
                tx.add_data(data);
                tx::TX_UPDATE_ACCOUNT_WASM
            }
            Transfer(data) => {
                tx.add_data(data);
                tx::TX_TRANSFER_WASM
            }
        };
        let code_hash = shell
            .read_storage_key(&storage::Key::wasm_hash(code_tag))
            .unwrap();
        tx.add_code_from_hash(code_hash, Some(code_tag.to_string()));

        tx.update_header(tx::data::TxType::Wrapper(Box::new(
            tx::data::WrapperTx::new(
                tx::data::Fee {
                    token: address::testing::nam(),
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                },
                signer.to_public(),
                1_000_000.into(),
            ),
        )));
        tx.add_section(tx::Section::Authorization(tx::Authorization::new(
            vec![tx.raw_header_hash()],
            [(0, signer.clone())].into_iter().collect(),
            None,
        )));

        txs_bytes.push(tx.to_bytes().into());
    }

    // Add a successful result for every tx
    let mut txs = Vec::with_capacity(txs_bytes.len());
    for tx in txs_bytes.into_iter() {
        let result = TxResult::default(); // default is success
        txs.push(ProcessedTx { tx, result });
    }

    // Run the txs via a `FinalizeBlock` request
    let proposer_pk = wallet::defaults::validator_keypair().to_public();
    let proposer_address_bytes = HEXUPPER
        .decode(proposer_pk.tm_raw_hash().as_bytes())
        .unwrap();
    let req = FinalizeBlock {
        txs,
        proposer_address: proposer_address_bytes,
        ..Default::default()
    };
    let _event = shell.finalize_block(req).unwrap();

    // Commit the block
    shell.commit();
}
