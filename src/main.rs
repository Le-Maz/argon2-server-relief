#![doc = include_str!("../README.md")]

use argon2::{
    Argon2, Block, Params, PasswordHash, PasswordVerifier, password_hash::phc::Decimal,
    password_hash::phc::Output, password_hash::phc::Salt, password_hash::phc::SaltString,
};
use serde::{Deserialize, Serialize};
use std::sync::mpsc;
use std::thread;

/// Initial payload sent from Server to Client containing the generation metadata.
#[derive(Serialize, Deserialize)]
struct ServerChallenge {
    /// Serialized directly as its string representation.
    #[serde(with = "salt_serde")]
    salt: SaltString,
    /// Serialized using its standard PHC string representation.
    #[serde(with = "params_serde")]
    params: Params,
}

/// Client-side payload containing the computationally expensive intermediate block.
#[derive(Serialize, Deserialize)]
struct ClientResponse {
    /// The internal 1024-byte state block serialized as raw 64-bit unsigned integers.
    #[serde(with = "block_serde")]
    final_block: Block,
}

/// Executed on the client: performs the heavy, memory-intensive phase of Argon2.
fn client_compute(password: &str, salt: &SaltString, params: Params) -> ClientResponse {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );

    let mut memory_blocks = vec![Block::default(); argon2.params().block_count()];
    let mut dummy_out = vec![0u8; params.output_len().unwrap_or(32)];

    let final_block = argon2
        .hash_password_into_block(
            password.as_bytes(),
            Salt::from(salt).as_ref(),
            &mut dummy_out,
            &mut memory_blocks,
        )
        .unwrap();

    ClientResponse { final_block }
}

/// Executed on the server: performs a lightweight, single-block finalization step.
fn server_finalize(final_block: Block, salt: SaltString, params: Params) -> String {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );

    let mut output_bytes = vec![0u8; params.output_len().unwrap_or(32)];
    argon2
        .finalize_block(&final_block, &mut output_bytes)
        .unwrap();

    PasswordHash {
        algorithm: argon2::ARGON2ID_IDENT,
        version: Some(Decimal::from(argon2::Version::V0x13 as u32)),
        params: params.try_into().unwrap(),
        salt: Some(Salt::from(salt)),
        hash: Some(Output::new(&output_bytes).unwrap()),
    }
    .to_string()
}

fn main() {
    let password = "my_secure_password".to_string();

    println!("=== SERVER RELIEF WORKFLOW WITH SERVER-SIDE SALT ===");

    // Setup two channels to simulate a bidirectional virtual I/O stream
    // server_tx -> client_rx
    let (server_tx, client_rx) = mpsc::channel::<Vec<u8>>();
    // client_tx -> server_rx
    let (client_tx, server_rx) = mpsc::channel::<Vec<u8>>();

    // 1. Client Thread
    let client_password = password.clone();
    let client_handle = thread::spawn(move || {
        println!("[Client] Waiting to receive salt and params from server stream...");
        let challenge_bytes = client_rx.recv().expect("Failed to read from server stream");

        let challenge: ServerChallenge = postcard::from_bytes(&challenge_bytes)
            .expect("Client failed to deserialize server challenge");
        println!("[Client] Received salt from server. Starting heavy computation...");

        let response = client_compute(&client_password, &challenge.salt, challenge.params);

        println!("[Client] Serializing intermediate block response...");
        let response_bytes = postcard::to_stdvec(&response).expect("Client serialization failed");

        println!(
            "[Client] Sending block back to server ({} bytes)...",
            response_bytes.len()
        );
        client_tx
            .send(response_bytes)
            .expect("Failed to write to client stream");
    });

    // 2. Server Thread
    let server_handle = thread::spawn(move || {
        println!("[Server] Generating fresh salt and parameters...");
        let salt = SaltString::generate();
        let params = Params::default();

        let challenge = ServerChallenge {
            salt: salt.clone(),
            params: params.clone(),
        };

        println!("[Server] Sending salt and parameters to client...");
        let challenge_bytes = postcard::to_stdvec(&challenge).expect("Server serialization failed");
        server_tx
            .send(challenge_bytes)
            .expect("Failed to write to server stream");

        println!("[Server] Waiting for client to finish heavy work...");
        let response_bytes = server_rx.recv().expect("Failed to read from client stream");

        println!("[Server] Received payload. Running near-zero-cost finalization step...");
        let response: ClientResponse = postcard::from_bytes(&response_bytes)
            .expect("Server failed to deserialize client response");

        let phc = server_finalize(response.final_block, salt, params);
        println!("[Server] Verification target hash computed successfully.");
        phc
    });

    // Collect handles
    client_handle.join().unwrap();
    let phc = server_handle.join().unwrap();

    println!("\n=== VERIFY (Standard Round-Trip on Main Thread) ===");
    println!("Final PHC String: {}", phc);
    let parsed = PasswordHash::new(&phc).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .expect("password verification failed");
    println!("Password verified successfully.");
}

/// Custom serialization helper module for the `argon2::Block` type.
mod block_serde {
    use argon2::Block;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(block: &Block, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        block.as_ref().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Block, D::Error>
    where
        D: Deserializer<'de>,
    {
        let u64_vec = Vec::<u64>::deserialize(deserializer)?;
        let mut block = Block::new();
        block.as_mut().copy_from_slice(&u64_vec);
        Ok(block)
    }
}

/// Custom serialization helper module for the `argon2::password_hash::SaltString` type.
mod salt_serde {
    use argon2::password_hash::phc::SaltString;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(salt: &SaltString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&salt.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SaltString, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SaltString::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Custom serialization helper module for the `argon2::Params` type.
mod params_serde {
    use argon2::{Params, password_hash::phc::ParamsString};
    use serde::{Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(params: &Params, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let phc_params =
            ParamsString::try_from(params.clone()).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(phc_params.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Params, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Params::from_str(&s).map_err(serde::de::Error::custom)
    }
}
