use std::collections::HashSet;
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

use anyhow::anyhow;
use async_trait::async_trait;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use rand::prelude::SliceRandom;
use rand::{thread_rng, Rng};
use sha2::Sha512;
use thiserror::Error;
use walletd_hd_key::slip44::Coin;
use walletd_hd_key::{HDKey, HDNetworkType};

use crate::monero_serialize::DoSerialize;
use crate::transaction::{TransactionPrefix, TxInToKey, TxSourceEntry, Txid};
use crate::{
    fee_utils, hash, key_image, monero_lws, payment_id, public_key, rct_types, transaction,
    Address, AddressType, KeyImage, MoneroAmount, MoneroPrivateKeys, MoneroPublicKeys, Network,
    PaymentId, PrivateKey, PublicKey, Seed, SerializedArchive, VarInt,
};
type HmacSha512 = Hmac<Sha512>;

use crate::monero_lws::{Error as MoneroLWSError, UnspentOutput, DEFAULT_DUST_THRESHOLD, FAKE_OUTPUTS_COUNT};
use crate::private_key::KEY_LEN;
use crate::rct_types::RctKey;
use crate::transaction::{GetOutsEntry, PendingTransaction, Priority, SendTransaction, TxDestinationEntry};

// Stubbed CryptoWallet trait
#[async_trait]
pub trait CryptoWallet {
    type AddressFormat;
    type BlockchainClient;
    type CryptoAmount;
    type NetworkType;
    type MnemonicSeed;

    fn crypto_type(&self) -> Coin;
    fn from_hd_key(hd_keys: &HDKey, address_format: Self::AddressFormat) -> Result<Self, Error>
    where
        Self: Sized;
    fn from_mnemonic_seed(
        mnemonic_seed: &Self::MnemonicSeed,
        network: Self::NetworkType,
        address_format: Self::AddressFormat,
    ) -> Result<Self, Error>
    where
        Self: Sized;
    fn public_address(&self) -> String;
    async fn balance(&self, blockchain_client: &Self::BlockchainClient) -> Result<Self::CryptoAmount, Error>;
    async fn transfer(
        &self,
        blockchain_client: &Self::BlockchainClient,
        send_amount: &Self::CryptoAmount,
        to_public_address: &str,
    ) -> Result<Txid, Error>;
}

const TX_EXTRA_TAG_PUBKEY: u8 = 0x01;
const HF_VERSION_VIEW_TAGS: u8 = 15;
const EXPECTED_MINIMUM_HF_VERSION: u8 = 15;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MoneroWallet {
    crypto_type: Coin,
    address_format: AddressType,
    network: Network,
    public_address: Address,
    private_keys: MoneroPrivateKeys,
    public_keys: MoneroPublicKeys,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Fake output has the same global index as the real output")]
    FakeOutputHasSameGlobalIndex,
    #[error("Not correct number of outputs for amount: expected {expected}, found {found}")]
    IncorrectNumberOfOutputs { expected: usize, found: usize },
    #[error("Monero::LWS Error: {0}")]
    MoneroLWS(#[from] MoneroLWSError),
    #[error("public_key Error: {0}")]
    PublicKey(#[from] public_key::Error),
    #[error("Error because sending zero amount")]
    SendingZeroAmount,
    #[error("Unable to meet the hard fork version expectated minimum fork version: {expected:?}, found {found:?}")]
    InvalidHardForkVersionAssumption { found: u8, expected: u8 },
    #[error("Only one payment id allowed per transaction")]
    OnlyOnePaymentIdAllowed,
    #[error("Error from handling payment id")]
    PaymentId(#[from] payment_id::Error),
    #[error("Insufficient funds, unable to complete transfer, needed {needed:?}, found {found:?}")]
    InsufficientFunds { needed: u64, found: u64 },
    #[error("Insufficient funds to cover fees and send amount, needed {needed:?}, found {found:?}")]
    InsufficientFundsForFee { needed: u64, found: u64 },
    #[error("Real output index is out of bounds")]
    RealOutputIndexOutOfBounds { index: usize, size: usize },
    #[error("Did not find real output index")]
    DidNotFindRealOutputIndex,
    #[error("Derived not equal real: index {index:?}, real_out {real_out:?}, derived_key {derived_key:?}, real_key {real_key:?}")]
    DerivedNotEqualReal { index: usize, real_out: u64, derived_key: String, real_key: String },
    #[error("Not all TxOutTargetVariant types are currently supported")]
    UnsupportedTxOutTargetVariant,
    #[error("Error converted from an anyhow::Error: {0}")]
    FromAnyhow(#[from] anyhow::Error),
    #[error("Error converted from the key_image module: {0}")]
    KeyImage(#[from] key_image::Error),
    #[error("Error from vectors having different lengths: vector 1 length {0:?} != vector 2 length {1:?}")]
    DifferentLengths(usize, usize),
    #[error("Transaction error, outputs value greater than inputs value: inputs {inputs:?}, outputs {outputs:?}")]
    TransactionValue { inputs: u64, outputs: u64 },
}

#[async_trait]
impl CryptoWallet for MoneroWallet {
    type AddressFormat = AddressType;
    type BlockchainClient = monero_lws::MoneroLWSConnection;
    type CryptoAmount = MoneroAmount;
    type NetworkType = Network;
    type MnemonicSeed = Seed;

    fn crypto_type(&self) -> Coin {
        self.crypto_type
    }

    fn from_hd_key(hd_keys: &HDKey, address_format: Self::AddressFormat) -> Result<Self, Error> {
        let mut entropy = HmacSha512::new_from_slice(b"bip-entropy-from-k")?;
        entropy.update(
            &hd_keys
                .extended_private_key
                .expect("extended private key data missing"),
        );

        let entropy_bytes = &entropy.finalize().into_bytes()[..KEY_LEN];
        let mut seed = [0u8; KEY_LEN];
        seed.copy_from_slice(entropy_bytes);
        let private_keys = MoneroPrivateKeys::from_seed(&seed)?;
        let public_keys = MoneroPublicKeys::from_private_keys(&private_keys);

        let network = match hd_keys.network {
            HDNetworkType::MainNet => Network::Mainnet,
            HDNetworkType::TestNet => Network::Stagenet,
        };

        let public_address = Address::new(&network, &public_keys, &address_format)?;

        Ok(Self {
            crypto_type: Coin::Monero,
            address_format,
            private_keys,
            public_keys,
            public_address,
            network,
        })
    }

    fn from_mnemonic_seed(
        mnemonic_seed: &Self::MnemonicSeed,
        network: Self::NetworkType,
        address_format: Self::AddressFormat,
    ) -> Result<Self, Error> {
        let seed = mnemonic_seed.as_bytes();
        let private_keys = MoneroPrivateKeys::from_seed(seed)?;
        let public_keys = MoneroPublicKeys::from_private_keys(&private_keys);
        let public_address = Address::new(&network, &public_keys, &address_format)?;

        Ok(Self {
            crypto_type: Coin::Monero,
            address_format,
            private_keys,
            public_keys,
            public_address,
            network,
        })
    }

    fn public_address(&self) -> String {
        self.public_address.to_string()
    }

    async fn balance(
        &self,
        blockchain_client: &Self::BlockchainClient,
    ) -> Result<Self::CryptoAmount, Error> {
        blockchain_client
            .login(
                &self.public_address(),
                &self.private_keys.view_key().to_string(),
                Some(true),
                None,
            )
            .await?;
        let unspent_outs_response = blockchain_client
            .get_unspent_outs(
                &self.public_address(),
                &self.private_keys.view_key().to_string(),
                0,
                true,
                0,
            )
            .await?;
        let unspent_outs = monero_lws::MoneroLWSConnection::to_unspent_outputs(self, &unspent_outs_response)?;
        let mut balance = MoneroAmount::from_piconero(0);
        for unspent_out in unspent_outs {
            balance += MoneroAmount::from_piconero(unspent_out.amount);
        }
        Ok(balance)
    }

    async fn transfer(
        &self,
        blockchain_client: &Self::BlockchainClient,
        send_amount: &Self::CryptoAmount,
        to_public_address: &str,
    ) -> Result<Txid, Error> {
        let receiver_address = Address::from_str(to_public_address)?;
        let send_amount_dest = TxDestinationEntry {
            amount: send_amount.as_piconero(),
            addr: receiver_address,
        };

        let unspent_outs_response = blockchain_client
            .get_unspent_outs(
                &self.public_address(),
                &self.private_keys.view_key().to_string(),
                0,
                true,
                0,
            )
            .await?;

        let per_byte_fee: u64 = unspent_outs_response["per_byte_fee"]
            .as_u64()
            .expect("per_byte_fee should be present");
        let fee_mask: u64 = unspent_outs_response["fee_mask"]
            .as_u64()
            .expect("fee_mask should be present");

        let fork_version: u8 = unspent_outs_response["fork_version"]
            .as_u64()
            .unwrap()
            .try_into()
            .expect("fork_version should be present");

        let priority = Priority::PriorityLow;
        let send_transfer = SendTransaction {
            destinations: vec![send_amount_dest],
            priority,
            sweep_all: false,
            payment_id: None,
            from_addr: self.public_address(),
            fork_version,
            per_byte_fee,
            fee_mask,
        };

        let mut unspent_outs = monero_lws::MoneroLWSConnection::to_unspent_outputs(self, &unspent_outs_response)?;
        let using_mix_outs = Self::light_wallet_get_outs(self, blockchain_client, &unspent_outs).await?;
        let mut pending_transaction = self.create_transaction(&send_transfer, &mut unspent_outs, &using_mix_outs)?;
        let signed_pending_tx = self.sign_tx(&mut pending_transaction)?;
        let mut serialized_tx = SerializedArchive::new();
        signed_pending_tx
            .pending_tx
            .tx
            .do_serialize(&mut serialized_tx)?;
        let raw_tx_hex = hex::encode(serialized_tx.data);

        let validated = signed_pending_tx.pending_tx.tx.validate()?;
        if validated {
            match blockchain_client
                .submit_raw_tx(
                    to_public_address,
                    &self.private_keys().view_key().to_string(),
                    &raw_tx_hex,
                )
                .await
            {
                Ok(response) => {
                    let tx_hash = response.as_str().expect("should be a string");
                    Ok(Txid(tx_hash.to_string()))
                }
                Err(e) => Err(Error::FromAnyhow(anyhow!("Error: {}", e))),
            }
        } else {
            Err(Error::FromAnyhow(anyhow!("Transaction is not valid")))
        }
    }
}

#[allow(dead_code)]
impl MoneroWallet {
    pub fn create_transaction(
        &self,
        send_transfer: &SendTransaction,
        unspent_outs: &mut Vec<UnspentOutput>,
        using_mix_outs: &[Vec<GetOutsEntry>],
    ) -> Result<PendingTransaction, Error> {
        if !send_transfer.sweep_all {
            for send_amount_to_dest in &send_transfer.destinations {
                let sending_amount = send_amount_to_dest.amount;
                if sending_amount == 0 {
                    return Err(Error::SendingZeroAmount);
                }
            }
        }

        if send_transfer.fork_version < EXPECTED_MINIMUM_HF_VERSION {
            return Err(Error::InvalidHardForkVersionAssumption {
                found: send_transfer.fork_version,
                expected: EXPECTED_MINIMUM_HF_VERSION,
            });
        }

        let mut sending_amounts: Vec<u64> = Vec::new();
        for send_amount_to_dest in &send_transfer.destinations {
            let sending_amount = send_amount_to_dest.amount;
            sending_amounts.push(sending_amount);
        }

        let use_per_byte_fee = true;
        let use_rct = true;
        let bulletproof = true;
        let bulletproof_plus = true;
        let clsag = true;
        let use_view_tags = send_transfer.fork_version >= HF_VERSION_VIEW_TAGS;
        let base_fee = send_transfer.per_byte_fee;
        let fee_quantization_mask = send_transfer.fee_mask;
        let mixin = FAKE_OUTPUTS_COUNT;

        let tx_key = PrivateKey::from_scalar(&Scalar::from_bytes_mod_order(thread_rng().gen()));
        let tx_key_pub = PublicKey::from_private_key(&tx_key);

        let mut extra_nonce: Vec<u8> = vec![];
        let mut tx_extra: Vec<u8> = vec![];

        if let Some(pid) = &send_transfer.payment_id {
            if !extra_nonce.is_empty() {
                return Err(Error::OnlyOnePaymentIdAllowed);
            }
            extra_nonce = pid.extra_nonce()?;
            pid.add_pid_to_tx_extra(&mut tx_extra)?;
        }

        for destination in &send_transfer.destinations {
            let dst_addr = &destination.addr;
            if let AddressType::Integrated(pid) = &dst_addr.format {
                if !extra_nonce.is_empty() {
                    return Err(Error::OnlyOnePaymentIdAllowed);
                }
                extra_nonce = pid.extra_nonce()?;
                let encrypted_pid = pid.encrypt_payment_id(&tx_key_pub, &tx_key)?;
                encrypted_pid.add_pid_to_tx_extra(&mut tx_extra)?;
            }
        }

        if extra_nonce.is_empty() && send_transfer.destinations.len() > 1 {
            let dummy_pid = PaymentId::from_slice(&[0u8; 8])?;
            let encrypted_pid = dummy_pid.encrypt_payment_id(&tx_key_pub, &tx_key)?;
            encrypted_pid.add_pid_to_tx_extra(&mut extra_nonce)?;
        }

        tx_extra.push(TX_EXTRA_TAG_PUBKEY);
        tx_extra.extend(tx_key_pub.as_slice());

        let max_estimated_fee = fee_utils::estimate_fee(
            use_per_byte_fee,
            use_rct,
            unspent_outs.len(),
            FAKE_OUTPUTS_COUNT,
            sending_amounts.len() + 1,
            tx_extra.len(),
            bulletproof,
            clsag,
            bulletproof_plus,
            use_view_tags,
            base_fee,
            fee_quantization_mask,
        );

        let mut final_total_wo_fee = MoneroAmount::from_piconero(0);
        for sending_amount in &sending_amounts {
            final_total_wo_fee += MoneroAmount::from_piconero(*sending_amount);
        }

        unspent_outs.sort_by(|a, b| b.amount.cmp(&a.amount));

        let mut using_outs: Vec<UnspentOutput> = Vec::new();
        let mut using_inds: Vec<usize> = Vec::new();

        let potential_total = if send_transfer.sweep_all {
            MoneroAmount::from_piconero(u64::MAX)
        } else {
            final_total_wo_fee + max_estimated_fee
        };

        let mut using_outs_amount = MoneroAmount::from_piconero(0);
        for (i, unspent_out) in unspent_outs.iter().enumerate() {
            if using_outs_amount >= potential_total {
                break;
            }
            if let Some(rct) = &unspent_out.rct {
                if !rct.is_empty() {
                    using_outs_amount += MoneroAmount::from_piconero(unspent_out.amount);
                    using_outs.push(unspent_out.clone());
                    using_inds.push(i);
                }
            }
        }

        if using_outs_amount < final_total_wo_fee {
            return Err(Error::InsufficientFunds {
                needed: final_total_wo_fee.as_piconero(),
                found: using_outs_amount.as_piconero(),
            });
        }

        let using_fee = fee_utils::estimate_fee(
            use_per_byte_fee,
            use_rct,
            using_outs.len(),
            FAKE_OUTPUTS_COUNT,
            sending_amounts.len() + 1,
            tx_extra.len(),
            bulletproof,
            clsag,
            bulletproof_plus,
            use_view_tags,
            base_fee,
            fee_quantization_mask,
        );

        let required_balance = final_total_wo_fee + using_fee;
        if using_outs_amount < required_balance {
            return Err(Error::InsufficientFundsForFee {
                needed: required_balance.as_piconero(),
                found: using_outs_amount.as_piconero(),
            });
        }

        let change_amount = using_outs_amount - required_balance;

        let change_dst = TxDestinationEntry {
            amount: change_amount.as_piconero(),
            addr: send_transfer.from_addr.clone(),
        };

        let mut needed_money = MoneroAmount::from_piconero(0);
        needed_money += final_total_wo_fee;
        needed_money += using_fee;

        let mut all_rct = true;

        let mut splitted_dsts = send_transfer.destinations.clone();
        splitted_dsts.push(change_dst.clone());

        let mut found_money = MoneroAmount::from_piconero(0);

        let mut sources: Vec<TxSourceEntry> = Vec::new();
        let out_index = 0;
        let mut vin: Vec<TxInToKey> = Vec::new();

        let mut in_contexts: Vec<transaction::InputGenerationContext> = Vec::new();
        let mut summary_inputs_money: u64 = 0;

        for (idx, unspent_out) in using_outs.iter().enumerate() {
            all_rct &= unspent_out.is_rct();
            found_money += MoneroAmount::from_piconero(unspent_out.amount);

            let mut src = TxSourceEntry {
                ..Default::default()
            };
            src.amount = unspent_out.amount;
            src.rct = unspent_out.is_rct();

            for n in 0..mixin + 1 {
                let outs_entry = &using_mix_outs[out_index][n];
                let ctkey = rct_types::CtKey {
                    dest: RctKey::from_slice(&outs_entry.1.to_bytes()),
                    mask: outs_entry.2,
                };
                let oe = transaction::OutputEntry(outs_entry.0, ctkey);
                src.outputs.push(oe);
            }

            let real_ind = src
                .outputs
                .iter()
                .position(|oe| oe.0 == unspent_out.global_index)
                .ok_or(Error::DidNotFindRealOutputIndex)?;
            let rct_tx_pub_key = PublicKey::from_str(&unspent_out.tx_pub_key.clone())?;
            let _rct_commit = &unspent_out.parse_rct_commit(self, &rct_tx_pub_key)?;
            let rct_mask = &unspent_out.parse_rct_mask(self, &rct_tx_pub_key)?;
            let rct_dest_public_key = PublicKey::from_str(&unspent_out.public_key)?;
            let _real_oe = transaction::OutputEntry(
                unspent_out.global_index,
                rct_types::CtKey {
                    dest: RctKey::from_slice(&rct_dest_public_key.to_bytes()),
                    mask: rct_types::RctKey::commit(src.amount, rct_mask),
                },
            );

            src.real_out_tx_key = PublicKey::from_str(&unspent_out.tx_pub_key.clone())?;
            src.real_output = real_ind as u64;
            src.real_output_in_tx_index = unspent_out.index;
            src.mask = *rct_mask;

            if src.real_output >= src.outputs.len() as u64 {
                return Err(Error::RealOutputIndexOutOfBounds {
                    index: src.real_output as usize,
                    size: src.outputs.len(),
                });
            }
            summary_inputs_money += src.amount;
            let k_image = KeyImage::new(
                &self.private_keys(),
                &src.real_out_tx_key,
                src.real_output_in_tx_index,
            )?;

            let out_key =
                PublicKey::from_slice(&src.outputs[src.real_output as usize].1.dest.to_bytes())?;

            if k_image.ephemeral_public_key != out_key {
                return Err(Error::DerivedNotEqualReal {
                    index: idx,
                    real_out: src.real_output,
                    derived_key: k_image.ephemeral_public_key.to_string(),
                    real_key: hex::encode(src.outputs[src.real_output as usize].1.dest.as_bytes()),
                });
            }

            in_contexts.push(transaction::InputGenerationContext {
                private_key: k_image.ephemeral_private_key,
                public_key: k_image.ephemeral_public_key,
            });

            let mut key_offsets: Vec<u64> = src.outputs.iter().map(|oe| oe.0).collect();
            TxInToKey::absolute_output_offsets_to_relative(&mut key_offsets);
            let input_to_key = TxInToKey {
                amount: src.amount,
                key_offsets: key_offsets.iter().map(|v| VarInt::<u64>(*v)).collect(),
                k_image,
            };

            sources.push(src);
            vin.push(input_to_key);
        }

        vin.sort_by(|a, b| a.k_image.key_image.cmp(&b.k_image.key_image));

        let mut amount_keys: Vec<RctKey> = Vec::new();
        let mut vout: Vec<transaction::TxOut> = Vec::new();
        let shuffle_outs = true;
        if shuffle_outs {
            let mut rng = thread_rng();
            splitted_dsts.shuffle(&mut rng);
        }

        let use_view_tags = send_transfer.fork_version >= HF_VERSION_VIEW_TAGS;

        let mut summary_outs_money = 0;
        for (output_index, dst_entr) in splitted_dsts.iter().enumerate() {
            let k_image = KeyImage::new(&self.private_keys(), &tx_key_pub, output_index as u64)?;
            let output_ephemeral_pub_key = k_image.ephemeral_public_key;
            let hash_scalar = k_image.key_derivation.hash_to_scalar(output_index as u64);

            amount_keys.push(RctKey::from_slice(hash_scalar.as_bytes()));
            summary_outs_money += dst_entr.amount;

            if !use_view_tags {
                vout.push(transaction::TxOut {
                    amount: dst_entr.amount,
                    target: transaction::TxOutTargetVariant::ToKey(transaction::TxOutToKey {
                        key: output_ephemeral_pub_key,
                    }),
                });
            } else {
                let view_tag = transaction::ViewTag::derive(&k_image.key_derivation, output_index as u64);
                vout.push(transaction::TxOut {
                    amount: dst_entr.amount,
                    target: transaction::TxOutTargetVariant::ToTaggedKey(transaction::TxOutToTaggedKey {
                        key: output_ephemeral_pub_key,
                        view_tag,
                    }),
                });
            }
        }

        let extra = transaction::RawExtraField(tx_extra);

        let mut tx_prefix = TransactionPrefix {
            version: 2,
            unlock_time: transaction::UnlockTime(0),
            vin,
            vout,
            extra,
        };

        if summary_outs_money > summary_inputs_money {
            return Err(Error::TransactionValue {
                inputs: summary_inputs_money,
                outputs: summary_outs_money,
            });
        }

        let rct_config = rct_types::RctConfig {
            range_proof_type: rct_types::RangeProofType::RangeProofPaddedBulletproof,
            bp_version: 4,
        };

        assert!(all_rct);

        let use_simple_rct = true;

        let mut amount_in: u64 = 0;
        let mut amount_out: u64 = 0;
        let mut in_sk: Vec<rct_types::CtKey> = Vec::new();
        in_sk.reserve(sources.len());
        let mut destinations: Vec<RctKey> = Vec::new();
        let mut in_amounts: Vec<u64> = Vec::new();
        let mut out_amounts: Vec<u64> = Vec::new();
        let mut index: Vec<u64> = Vec::new();
        for i in 0..sources.len() {
            let amount = sources[i].amount;
            amount_in += amount;
            in_amounts.push(amount);
            index.push(sources[i].real_output);
            in_sk.push(rct_types::CtKey {
                dest: RctKey::from_slice(in_contexts[i].private_key.as_slice()),
                mask: sources[i].mask,
            });
        }

        for tx_vout in tx_prefix.vout.iter() {
            out_amounts.push(tx_vout.amount);
            amount_out += tx_vout.amount;
            match &tx_vout.target {
                transaction::TxOutTargetVariant::ToKey(target) => {
                    let output_public_key = RctKey::from_slice(target.key.as_slice());
                    destinations.push(output_public_key);
                }
                transaction::TxOutTargetVariant::ToTaggedKey(target) => {
                    let output_public_key = RctKey::from_slice(target.key.as_slice());
                    destinations.push(output_public_key);
                }
                _ => return Err(Error::UnsupportedTxOutTargetVariant),
            }
        }

        let mut mix_ring: Vec<Vec<rct_types::CtKey>> = Vec::new();
        mix_ring.resize(sources.len(), Vec::new());
        if use_simple_rct {
            for i in 0..sources.len() {
                mix_ring[i].resize(sources[i].outputs.len(), rct_types::CtKey::default());
                for n in 0..sources[i].outputs.len() {
                    mix_ring[i][n] = sources[i].outputs[n].1.clone();
                }
            }
        }

        for (i, tx_vin) in tx_prefix.vin.iter_mut().enumerate() {
            if sources[i].rct {
                tx_vin.amount = 0;
            }
        }

        for tx_vout in tx_prefix.vout.iter_mut() {
            tx_vout.amount = 0;
        }

        let mut tx_prefix_serialized: SerializedArchive = SerializedArchive::new();
        tx_prefix.do_serialize(&mut tx_prefix_serialized)?;

        let tx_prefix_hash = hash::keccak256(&tx_prefix_serialized.to_bytes());
        let message = RctKey::from_slice(&tx_prefix_hash);
        let mut out_sk: Vec<rct_types::CtKey> = Vec::new();
        let rct_signatures = rct_types::RctSig::generate_rct_simple(
            &message,
            &in_sk,
            &destinations,
            &in_amounts,
            &out_amounts,
            amount_in - amount_out,
            &mix_ring,
            &amount_keys,
            &index,
            &mut out_sk,
            rct_config,
        )?;

        let tx = transaction::Transaction {
            prefix: tx_prefix.clone(),
            prunable_hash_valid: false,
            hash_valid: false,
            blob_size_valid: false,
            signatures: Vec::new(),
            rct_signatures,
        };

        if tx.prefix.vout.len() != out_sk.len() {
            return Err(Error::DifferentLengths(tx.prefix.vout.len(), out_sk.len()));
        }

        let tx_construction_data = transaction::TxConstructionData {
            unlock_time: tx.prefix.unlock_time,
            use_rct: true,
            rct_config,
            sources,
            change_dts: change_dst,
            splitted_dsts: splitted_dsts.clone(),
            selected_transfers: vec![0],
            extra: tx_prefix.extra.clone(),
            use_view_tags,
            dests: send_transfer.destinations.clone(),
            subaddr_indices: HashSet::new(),
            subadr_account: 0,
        };

        let pending_tx = transaction::PendingTx {
            fee: using_fee.as_piconero(),
            dust_added_to_fee: false,
            change_dts: tx_construction_data.change_dts.clone(),
            selected_transfers: tx_construction_data.selected_transfers.clone(),
            key_images: String::new(),
            dests: tx_construction_data.dests.clone(),
            tx_key,
            additional_tx_keys: Vec::new(),
            tx,
            dust: DEFAULT_DUST_THRESHOLD,
            multisig_sigs: Vec::new(),
            multisig_tx_key_entropy: None,
            construction_data: tx_construction_data,
        };

        Ok(PendingTransaction {
            status: transaction::Status::StatusOk,
            priority: send_transfer.priority,
            pending_tx,
            signers: HashSet::new(),
            key_images: HashSet::new(),
        })
    }

    #[allow(dead_code)]
    pub fn sign_tx(
        &self,
        unsigned_pending_tx: &mut PendingTransaction,
    ) -> Result<PendingTransaction, Error> {
        if !unsigned_pending_tx.signers.is_empty() {
            return Err(Error::FromAnyhow(anyhow!("Transaction already has signers")));
        }

        let mut key_images: HashSet<KeyImage> = HashSet::new();
        let tx_pub_key = PublicKey::from_private_key(&unsigned_pending_tx.pending_tx.tx_key);

        assert!(unsigned_pending_tx.pending_tx.additional_tx_keys.is_empty());

        for (i, _vout) in unsigned_pending_tx.pending_tx.tx.prefix.vout.iter().enumerate() {
            let key_image_info = KeyImage::new(&self.private_keys, &tx_pub_key, i as u64)?;
            key_images.insert(key_image_info);
        }
        let mut signed_pending_tx = unsigned_pending_tx.clone();
        signed_pending_tx.key_images = key_images;
        Ok(signed_pending_tx)
    }

    #[allow(dead_code)]
    pub fn public_keys(&self) -> MoneroPublicKeys {
        self.public_keys
    }

    #[allow(dead_code)]
    pub fn private_keys(&self) -> MoneroPrivateKeys {
        self.private_keys
    }

    #[allow(dead_code)]
    pub fn public_address(&self) -> Address {
        self.public_address.clone()
    }

    #[allow(dead_code)]
    pub fn network(&self) -> Network {
        self.network
    }

    #[allow(dead_code)]
    pub async fn light_wallet_get_outs(
        &self,
        blockchain_client: &monero_lws::MoneroLWSConnection,
        using_outs: &Vec<UnspentOutput>,
    ) -> Result<Vec<Vec<GetOutsEntry>>, Error> {
        println!("In light_wallet_get_outs");
        let mut vec_needed: Vec<u64> = Vec::new();

        for using_out in using_outs {
            if using_out.is_rct() {
                vec_needed.push(0);
            } else {
                vec_needed.push(using_out.amount);
            }
        }

        let random_outs_server = blockchain_client.get_random_outs(vec_needed).await.unwrap();

        for mix_out in &random_outs_server {
            if mix_out.outputs.len() != FAKE_OUTPUTS_COUNT + 1 {
                return Err(Error::IncorrectNumberOfOutputs {
                    expected: FAKE_OUTPUTS_COUNT,
                    found: mix_out.outputs.len(),
                });
            }
        }

        let mut outs: Vec<Vec<GetOutsEntry>> = Vec::new();
        for (idx, using_out) in using_outs.iter().enumerate() {
            let tx_pub_key = PublicKey::from_str(&using_out.public_key)?;
            let _rct_commit = using_out.parse_rct_commit(self, &tx_pub_key)?;
            let rct_mask = using_out.parse_rct_mask(self, &tx_pub_key)?;
            let real_output = GetOutsEntry(
                using_out.global_index,
                PublicKey::from_str(&using_out.public_key)?,
                RctKey::commit(using_out.amount, &rct_mask),
            );
            let mut idx_out = vec![real_output];

            let mut rng = rand::thread_rng();
            let mut random_order: Vec<usize> = (0..FAKE_OUTPUTS_COUNT).collect();
            random_order.shuffle(&mut rng);
            for i in random_order {
                let amount_key = idx;
                let global_index = &random_outs_server[amount_key].outputs[i].global_index;
                let real_index = using_out.global_index;
                if *global_index == real_index {
                    return Err(Error::FakeOutputHasSameGlobalIndex);
                }

                let output_public_key =
                    PublicKey::from_str(&random_outs_server[amount_key].outputs[i].public_key)?;
                let rct_commit = using_out.parse_rct_commit(self, &output_public_key)?;
                let _mask = using_out.parse_rct_mask(self, &output_public_key)?;

                idx_out.push(GetOutsEntry(*global_index, output_public_key, rct_commit));
            }
            idx_out.sort_by(|a, b| a.0.cmp(&b.0));
            outs.push(idx_out);
        }
        Ok(outs)
    }
}

impl Display for MoneroWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Monero Wallet")?;
        writeln!(f, " Network: {:?}", self.network)?;
        if let Some(private_spend_key) = self.private_keys.spend_key() {
            writeln!(f, " Private Spend Key: {}", private_spend_key)?;
        }
        writeln!(f, " Private View Key: {}", self.private_keys.view_key())?;
        if let Some(public_spend_key) = self.public_keys.spend_key() {
            writeln!(f, " Public Spend Key: {}", public_spend_key)?;
        }
        if let Some(public_view_key) = self.public_keys.view_key() {
            writeln!(f, " Public View Key: {}", public_view_key)?;
        }
        writeln!(f, " Public Address: {}", self.public_address)?;
        Ok(())
    }
}