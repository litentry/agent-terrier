//! Minimal legacy (pre-EIP-1559) transaction RLP encoding + EIP-155 signing.
//!
//! Heima accepts legacy txs and its `eth_estimateGas` reverts on `handleOps`
//! (see `docs/heima-eth-gap.md`), so the bundler signs a fixed-gas-limit
//! legacy tx and submits it via `eth_sendRawTransaction` — no alloy/ethers
//! (their receipt/header parsers crash on Heima's mixHash-less responses).
//! Hand-rolled RLP, golden-tested against the EIP-155 reference vector.

use agentkeys_core::device_crypto::keccak256;
use anyhow::{anyhow, Result};
use k256::ecdsa::SigningKey;

/// RLP-encode a byte string.
fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    match b.len() {
        1 if b[0] < 0x80 => vec![b[0]],
        len if len <= 55 => {
            let mut out = vec![0x80 + len as u8];
            out.extend_from_slice(b);
            out
        }
        len => {
            let len_be: Vec<u8> = strip_leading_zeros(&(len as u64).to_be_bytes());
            let mut out = vec![0xb7 + len_be.len() as u8];
            out.extend_from_slice(&len_be);
            out.extend_from_slice(b);
            out
        }
    }
}

/// RLP-encode a list whose items are ALREADY RLP-encoded.
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    match payload.len() {
        len if len <= 55 => {
            let mut out = vec![0xc0 + len as u8];
            out.extend_from_slice(&payload);
            out
        }
        len => {
            let len_be: Vec<u8> = strip_leading_zeros(&(len as u64).to_be_bytes());
            let mut out = vec![0xf7 + len_be.len() as u8];
            out.extend_from_slice(&len_be);
            out.extend_from_slice(&payload);
            out
        }
    }
}

fn strip_leading_zeros(b: &[u8]) -> Vec<u8> {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[first..].to_vec()
}

/// RLP-encode an unsigned integer (minimal big-endian; zero → empty string).
fn rlp_uint(n: u128) -> Vec<u8> {
    rlp_bytes(&strip_leading_zeros(&n.to_be_bytes()))
}

/// An unsigned legacy transaction (the bundler's outer `handleOps` carrier).
#[derive(Clone, Debug)]
pub struct LegacyTx {
    pub nonce: u128,
    pub gas_price: u128,
    pub gas_limit: u128,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

impl LegacyTx {
    fn base_fields(&self) -> Vec<Vec<u8>> {
        vec![
            rlp_uint(self.nonce),
            rlp_uint(self.gas_price),
            rlp_uint(self.gas_limit),
            rlp_bytes(&self.to),
            rlp_uint(self.value),
            rlp_bytes(&self.data),
        ]
    }

    /// EIP-155 signing hash: `keccak(rlp([nonce,gasPrice,gas,to,value,data,chainId,0,0]))`.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut fields = self.base_fields();
        fields.push(rlp_uint(self.chain_id as u128));
        fields.push(rlp_uint(0));
        fields.push(rlp_uint(0));
        keccak256(&rlp_list(&fields))
    }

    /// Sign and return the raw tx bytes for `eth_sendRawTransaction`, plus the
    /// tx hash (`keccak(raw)`).
    pub fn sign(&self, sk: &SigningKey) -> Result<(Vec<u8>, [u8; 32])> {
        let (sig, recid) = sk
            .sign_prehash_recoverable(&self.signing_hash())
            .map_err(|e| anyhow!("sign legacy tx: {e}"))?;
        let v = self.chain_id as u128 * 2 + 35 + recid.to_byte() as u128;
        let r = sig.r().to_bytes();
        let s = sig.s().to_bytes();
        let mut fields = self.base_fields();
        fields.push(rlp_uint(v));
        fields.push(rlp_bytes(&strip_leading_zeros(&r)));
        fields.push(rlp_bytes(&strip_leading_zeros(&s)));
        let raw = rlp_list(&fields);
        let hash = keccak256(&raw);
        Ok((raw, hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The EIP-155 reference vector (chain 1, key 0x46×32).
    #[test]
    fn signs_the_eip155_reference_vector() {
        let sk = SigningKey::from_slice(&[0x46; 32]).unwrap();
        let tx = LegacyTx {
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: hex::decode("3535353535353535353535353535353535353535")
                .unwrap()
                .try_into()
                .unwrap(),
            value: 1_000_000_000_000_000_000,
            data: vec![],
            chain_id: 1,
        };
        assert_eq!(
            hex::encode(tx.signing_hash()),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );
        let (raw, _hash) = tx.sign(&sk).unwrap();
        assert_eq!(
            hex::encode(raw),
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
    }

    #[test]
    fn rlp_primitives() {
        assert_eq!(rlp_uint(0), vec![0x80]);
        assert_eq!(rlp_uint(0x7f), vec![0x7f]);
        assert_eq!(rlp_uint(0x80), vec![0x81, 0x80]);
        assert_eq!(rlp_bytes(b""), vec![0x80]);
        assert_eq!(rlp_bytes(&[0u8]), vec![0x00]);
        let long = vec![0xaa; 60];
        let enc = rlp_bytes(&long);
        assert_eq!(&enc[..2], &[0xb8, 60]);
    }
}
