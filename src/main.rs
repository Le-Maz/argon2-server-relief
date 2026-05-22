#![doc = include_str!("../README.md")]

use std::sync::mpsc;

use argon2::{
    Argon2, Block, Params, PasswordHash, PasswordVerifier,
    password_hash::phc::{Decimal, Output, Salt, SaltString},
};

/// Client payload containing processed intermediate memory state structures.
struct ClientPayload {
    final_block: Block,
    salt: SaltString,
    params: Params,
}

type ServerResponse = Result<String, String>;

/// Emulates client execution environments performing heavy memory allocation tasks.
fn client_thread(password: &str, params: Params, tx: mpsc::SyncSender<ClientPayload>) {
    let salt = SaltString::generate();

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );

    let mut memory_blocks = vec![Block::default(); argon2.params().block_count()];

    let output_len = params.output_len().unwrap_or(32);
    let mut dummy_out = vec![0u8; output_len];

    let salt_decoded = Salt::from(&salt);

    let final_block = argon2
        .hash_password_into_block(
            password.as_bytes(),
            salt_decoded.as_ref(),
            &mut dummy_out,
            &mut memory_blocks,
        )
        .unwrap();

    tx.send(ClientPayload {
        final_block,
        salt,
        params,
    })
    .unwrap();
}

/// Emulates lightweight server verification endpoints completing hash storage.
fn server_thread(rx: mpsc::Receiver<ClientPayload>, response_tx: mpsc::SyncSender<ServerResponse>) {
    let ClientPayload {
        final_block,
        salt,
        params,
    } = rx.recv().unwrap();

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );

    let output_len = params.output_len().unwrap_or(32);
    let mut output_bytes = vec![0u8; output_len];

    argon2
        .finalize_block(&final_block, &mut output_bytes)
        .unwrap();

    let salt_ref = Salt::from(salt);
    let hash = Output::new(&output_bytes).unwrap();

    let phc = PasswordHash {
        algorithm: argon2::ARGON2ID_IDENT,
        version: Some(Decimal::from(argon2::Version::V0x13 as u32)),
        params: params.try_into().unwrap(),
        salt: Some(salt_ref),
        hash: Some(hash),
    };

    response_tx.send(Ok(phc.to_string())).unwrap();
}

/// Orchestrates secure communication threads modeling request-response round-trips.
fn register(password: &str) -> String {
    let (client_tx, server_rx) = mpsc::sync_channel::<ClientPayload>(1);
    let (response_tx, response_rx) = mpsc::sync_channel::<ServerResponse>(1);

    let params = Params::default();
    let password = password.to_owned();

    let client = std::thread::spawn(move || client_thread(&password, params, client_tx));
    let server = std::thread::spawn(move || server_thread(server_rx, response_tx));

    client.join().unwrap();
    server.join().unwrap();

    response_rx
        .recv()
        .unwrap()
        .precondition_isolated("registration failed")
}

trait UnpackResultExt<T> {
    fn precondition_isolated(self, msg: &str) -> T;
}

impl<T, E> UnpackResultExt<T> for Result<T, E> {
    fn precondition_isolated(self, msg: &str) -> T {
        match self {
            Ok(val) => val,
            Err(_) => panic!("{}", msg),
        }
    }
}

fn main() {
    let password = "my_secure_password";

    println!("=== REGISTER ===");
    let phc = register(password);
    println!("Stored PHC: {}", phc);

    println!("\n=== VERIFY (native round-trip check) ===");
    let parsed = PasswordHash::new(&phc).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .expect("password verification failed");
    println!("Password verified successfully.");
}
