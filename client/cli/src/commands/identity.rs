use sp_core::{Pair, ecdsa::PublicKey};
use sp_io::hashing::keccak_256;
use crate::Error;
use structopt::StructOpt;

/// Identity utilities for the cli.
#[derive(Debug, StructOpt)]
pub enum IdentitySubcommand {
    /// Generate a new identity for bool-network with ETH format
    /// Return params contains Seed, Pubkey, AccountId
    Generate,
}

impl IdentitySubcommand {
    /// run the key subcommands
    pub fn run(&self) -> Result<(), Error> {
        match self {
            IdentitySubcommand::Generate => {
                let (pair, seed): (sp_core::ecdsa::Pair, [u8; 32]) = Pair::generate();
                let compress_pk = pair.public().0;
                let pk = PublicKey::parse_compressed(&compress_pk).map_err(|e| Error::Input(e.to_string()))?.serialize();
                let address = "0x".to_string() + &hex::encode(&keccak_256(&pk[1..])[12..]);
                let public_key = "0x".to_string() + &hex::encode(&compress_pk);
                let secret_seed = "0x".to_string() + & &hex::encode(&seed);
                println!(
                    "Secret seed:      {}\n  \
					Public key (hex): {}\n  \
					Account ID:       {}",
                    secret_seed,
                    public_key,
                    address,
                );
                Ok(())
            },
        }
    }
}
