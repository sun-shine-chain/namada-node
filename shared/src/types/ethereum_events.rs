//! Types representing data intended for Anoma via Ethereum events

pub mod vote_extensions;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::Uint as ethUint;
use eyre::{eyre, Context};
use namada_proof_of_stake::types::VotingPower;

use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::token::Amount;

/// Anoma native type to replace the ethabi::Uint type
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct Uint(pub [u64; 4]);

impl From<ethUint> for Uint {
    fn from(value: ethUint) -> Self {
        Self(value.0)
    }
}

impl From<Uint> for ethUint {
    fn from(value: Uint) -> Self {
        Self(value.0)
    }
}

impl From<u64> for Uint {
    fn from(value: u64) -> Self {
        ethUint::from(value).into()
    }
}

/// Representation of address on Ethereum. The inner value is the last 20 bytes
/// of the public key that controls the account.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct EthAddress(pub [u8; 20]);

impl EthAddress {
    /// The canonical way we represent an [`EthAddress`] in storage keys. A
    /// 40-character lower case hexadecimal address prefixed by '0x'.
    /// e.g. "0x6b175474e89094c44da98b954eedeac495271d0f"
    pub fn to_canonical(&self) -> String {
        format!("{:?}", ethabi::ethereum_types::Address::from(&self.0))
    }
}

impl FromStr for EthAddress {
    type Err = eyre::Error;

    /// Parses an [`EthAddress`] from a standard hex-encoded Ethereum address
    /// string. e.g. "0x6B175474E89094C44Da98b954EedeAC495271d0F"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let h160 = ethabi::ethereum_types::Address::from_str(s)
            .wrap_err_with(|| eyre!("couldn't parse Ethereum address {}", s))?;
        Ok(Self(h160.into()))
    }
}

/// A Keccak hash
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct KeccakHash(pub [u8; 32]);

/// An Ethereum event to be processed by the Anoma ledger
#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Hash,
    Ord,
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub enum EthereumEvent {
    /// Event transferring batches of ether or Ethereum based ERC20 tokens
    /// from Ethereum to wrapped assets on Anoma
    TransfersToNamada {
        /// Monotonically increasing nonce
        #[allow(dead_code)]
        nonce: Uint,
        /// The batch of transfers
        #[allow(dead_code)]
        transfers: Vec<TransferToNamada>,
    },
    /// A confirmation event that a batch of transfers have been made
    /// from Anoma to Ethereum
    TransfersToEthereum {
        /// Monotonically increasing nonce
        #[allow(dead_code)]
        nonce: Uint,
        /// The batch of transfers
        #[allow(dead_code)]
        transfers: Vec<TransferToEthereum>,
    },
    /// Event indication that the validator set has been updated
    /// in the governance contract
    ValidatorSetUpdate {
        /// Monotonically increasing nonce
        #[allow(dead_code)]
        nonce: Uint,
        /// Hash of the validators in the bridge contract
        #[allow(dead_code)]
        bridge_validator_hash: KeccakHash,
        /// Hash of the validators in the governance contract
        #[allow(dead_code)]
        governance_validator_hash: KeccakHash,
    },
    /// Event indication that a new smart contract has been
    /// deployed
    NewContract {
        /// Name of the contract
        #[allow(dead_code)]
        name: String,
        /// Address of the contract on Ethereum
        #[allow(dead_code)]
        address: EthAddress,
    },
    /// Event indicating that a smart contract has been updated
    UpgradedContract {
        /// Name of the contract
        #[allow(dead_code)]
        name: String,
        /// Address of the contract on Ethereum
        #[allow(dead_code)]
        address: EthAddress,
    },
    /// Event indication a new Ethereum based token has been whitelisted for
    /// transfer across the bridge
    UpdateBridgeWhitelist {
        /// Monotonically increasing nonce
        #[allow(dead_code)]
        nonce: Uint,
        /// Tokens to be allowed to be transferred across the bridge
        #[allow(dead_code)]
        whitelist: Vec<TokenWhitelist>,
    },
}

impl EthereumEvent {
    /// SHA256 of the Borsh serialization of the [`EthereumEvent`].
    pub fn hash(&self) -> Result<Hash, std::io::Error> {
        let bytes = self.try_to_vec()?;
        Ok(Hash::sha256(&bytes))
    }
}

/// An event transferring some kind of value from Ethereum to Anoma
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Hash,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct TransferToNamada {
    /// Quantity of the ERC20 token in the transfer
    pub amount: Amount,
    /// Address of the smart contract issuing the token
    pub asset: EthAddress,
    /// The address receiving wrapped assets on Anoma
    pub receiver: Address,
}

/// An event transferring some kind of value from Anoma to Ethereum
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct TransferToEthereum {
    /// Quantity of wrapped Asset in the transfer
    pub amount: Amount,
    /// Address of the smart contract issuing the token
    pub asset: EthAddress,
    /// The address receiving assets on Ethereum
    pub receiver: EthAddress,
}

/// struct for whitelisting a token from Ethereum.
/// Includes the address of issuing contract and
/// a cap on the max amount of this token allowed to be
/// held by the bridge.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
#[allow(dead_code)]
pub struct TokenWhitelist {
    /// Address of Ethereum smart contract issuing token
    pub token: EthAddress,
    /// Maximum amount of token allowed on the bridge
    pub cap: Amount,
}

/// Represents an Ethereum event being seen by some validators
#[derive(
    Debug,
    Clone,
    Ord,
    PartialOrd,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct EthMsgUpdate {
    /// the event being seen
    pub body: EthereumEvent,
    /// addresses of the validators who have just seen this event
    /// we use [`BTreeSet`] even though ordering is not important here, so that
    /// we can derive [`Hash`] for [`EthMsgUpdate`]
    pub seen_by: BTreeSet<Address>,
}

impl From<vote_extensions::MultiSignedEthEvent> for EthMsgUpdate {
    fn from(
        vote_extensions::MultiSignedEthEvent { event, signers }: vote_extensions::MultiSignedEthEvent,
    ) -> Self {
        Self {
            body: event,
            seen_by: signers.into_iter().collect(),
        }
    }
}

/// The data that is passed to tx_eth_bridge.wasm
#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TxEthBridgeData {
    /// Updates to be applied to /eth_msgs storage. The order in which updates
    /// are applied does not matter.
    pub updates: HashSet<EthMsgUpdate>,
    /// Total voting power for the epoch in which the Ethereum events were
    /// voted for.
    pub total_voting_power: VotingPower,
    /// Voting powers for each validator which is seeing an event in `updates`.
    pub voting_powers: HashMap<Address, VotingPower>,
}

#[allow(missing_docs)]
/// Test helpers
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::vote_extensions::*;
    use super::*;
    use crate::types::storage::Epoch;
    use crate::types::token::Amount;

    pub const DAI_ERC20_ETH_ADDRESS_CHECKSUMMED: &str =
        "0x6B175474E89094C44Da98b954EedeAC495271d0F";
    pub const DAI_ERC20_ETH_ADDRESS: EthAddress = EthAddress([
        107, 23, 84, 116, 232, 144, 148, 196, 77, 169, 139, 149, 78, 237, 234,
        196, 149, 39, 29, 15,
    ]);

    pub fn arbitrary_eth_address() -> EthAddress {
        DAI_ERC20_ETH_ADDRESS
    }

    pub fn arbitrary_fractional_voting_power() -> FractionalVotingPower {
        FractionalVotingPower::new(1, 3).unwrap()
    }

    pub fn arbitrary_nonce() -> Uint {
        123.into()
    }

    pub fn arbitrary_amount() -> Amount {
        Amount::from(1_000)
    }

    pub fn arbitrary_voting_power() -> VotingPower {
        VotingPower::from(1_000)
    }

    pub fn arbitrary_epoch() -> Epoch {
        Epoch(100)
    }

    /// A [`EthereumEvent::TransfersToNamada`] containing a single transfer of
    /// some arbitrary ERC20
    pub fn arbitrary_single_transfer(
        nonce: Uint,
        receiver: Address,
    ) -> EthereumEvent {
        EthereumEvent::TransfersToNamada {
            nonce,
            transfers: vec![TransferToNamada {
                amount: arbitrary_amount(),
                asset: arbitrary_eth_address(),
                receiver,
            }],
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::{BTreeSet, HashSet};
    use std::str::FromStr;

    use super::vote_extensions::MultiSignedEthEvent;
    use super::*;
    use crate::types::address;
    use crate::types::ethereum_events::testing::{
        arbitrary_nonce, arbitrary_single_transfer,
    };

    #[test]
    fn test_from_multi_signed_eth_event_for_eth_msg_update() {
        let sole_validator = address::testing::established_address_1();
        let receiver = address::testing::established_address_2();
        let event = arbitrary_single_transfer(arbitrary_nonce(), receiver);
        let with_signers = MultiSignedEthEvent {
            event: event.clone(),
            signers: HashSet::from_iter(vec![sole_validator.clone()]),
        };
        let expected = EthMsgUpdate {
            body: event.clone(),
            seen_by: BTreeSet::from_iter(vec![sole_validator]),
        };

        let update: EthMsgUpdate = with_signers.into();

        assert_eq!(update, expected);
    }

    #[test]
    fn test_eth_address_to_canonical() {
        let canonical = testing::DAI_ERC20_ETH_ADDRESS.to_canonical();

        assert_eq!(
            testing::DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase(),
            canonical,
        );
    }

    #[test]
    fn test_eth_address_from_str() {
        let addr =
            EthAddress::from_str(testing::DAI_ERC20_ETH_ADDRESS_CHECKSUMMED)
                .unwrap();

        assert_eq!(testing::DAI_ERC20_ETH_ADDRESS, addr);
    }

    #[test]
    fn test_eth_address_from_str_error() {
        let result = EthAddress::from_str(
            "arbitrary string which isn't an Ethereum address",
        );

        assert!(result.is_err());
    }
}
