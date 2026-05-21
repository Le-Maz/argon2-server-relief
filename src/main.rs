#![doc = include_str!("../README.md")]

use std::sync::mpsc;

use argon2::{
    Argon2, Block, Params, PasswordHash, PasswordVerifier,
    password_hash::{Decimal, SaltString},
};
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};

pub(crate) const SYNC_POINTS: usize = 4;

/// Internal layout calculations for Argon2 memory structure mapping.
pub trait Argon2Privates {
    fn lanes(&self) -> usize;
    fn lane_length(&self) -> usize;
    fn segment_length(&self) -> usize;
    fn block_count(&self) -> usize;
}

impl Argon2Privates for Argon2<'_> {
    fn lanes(&self) -> usize {
        self.params().p_cost() as usize
    }

    fn lane_length(&self) -> usize {
        self.segment_length() * SYNC_POINTS
    }

    fn segment_length(&self) -> usize {
        let m_cost = self.params().m_cost() as usize;
        let memory_blocks = m_cost.max(2 * SYNC_POINTS * self.lanes());
        memory_blocks / (self.lanes() * SYNC_POINTS)
    }

    fn block_count(&self) -> usize {
        self.segment_length() * self.lanes() * SYNC_POINTS
    }
}

/// Computes the Argon2 variable-length digest using BLAKE2b variants.
fn blake2b_long(inputs: &[&[u8]], out: &mut [u8]) {
    let outlen_bytes = (out.len() as u32).to_le_bytes();

    if out.len() <= 64 {
        let mut hasher = Blake2bVar::new(out.len()).unwrap();
        hasher.update(&outlen_bytes);
        for input in inputs {
            hasher.update(input);
        }
        hasher.finalize_variable(out).unwrap();
        return;
    }

    use blake2::{Blake2b512, Digest};

    let mut digest = Blake2b512::new();
    Digest::update(&mut digest, outlen_bytes);
    for input in inputs {
        Digest::update(&mut digest, input);
    }
    let mut last_output = digest.finalize();

    out[..32].copy_from_slice(&last_output[..32]);
    let mut counter = 32usize;
    let out_len = out.len();

    for chunk in out[32..].chunks_exact_mut(32).take_while(|_| {
        counter += 32;
        out_len - counter > 64
    }) {
        last_output = Blake2b512::digest(last_output);
        chunk.copy_from_slice(&last_output[..32]);
    }

    let last_block_size = out_len - counter;
    let mut var_digest = Blake2bVar::new(last_block_size).unwrap();
    Update::update(&mut var_digest, &last_output);
    var_digest.finalize_variable(&mut out[counter..]).unwrap();
}

/// Client payload containing processed intermediate memory state structures.
struct ClientPayload {
    blockhash_bytes: [u8; Block::SIZE],
    salt: SaltString,
    params: Params,
}

type ServerResponse = Result<String, String>;

/// Emulates client execution environments performing heavy memory allocation tasks.
fn client_thread(password: &str, params: Params, tx: mpsc::SyncSender<ClientPayload>) {
    let salt = {
        use argon2::password_hash::rand_core::OsRng;
        SaltString::generate(&mut OsRng)
    };

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );

    let mut salt_arr = [0u8; 64];
    let salt_bytes = salt.decode_b64(&mut salt_arr).unwrap();
    let mut memory_blocks = vec![Block::default(); argon2.block_count()];

    let output_len = params.output_len().unwrap_or(32);
    let mut dummy_out = vec![0u8; output_len];

    argon2
        .hash_password_into_with_memory(
            password.as_bytes(),
            salt_bytes,
            &mut dummy_out,
            &mut memory_blocks,
        )
        .unwrap();

    let lane_length = argon2.lane_length();
    let mut blockhash = memory_blocks[lane_length - 1];
    for l in 1..argon2.lanes() {
        blockhash ^= &memory_blocks[l * lane_length + (lane_length - 1)];
    }

    let mut blockhash_bytes = [0u8; Block::SIZE];
    for (chunk, v) in blockhash_bytes.chunks_mut(8).zip(blockhash.as_ref().iter()) {
        chunk.copy_from_slice(&v.to_le_bytes());
    }

    tx.send(ClientPayload {
        blockhash_bytes,
        salt,
        params,
    })
    .unwrap();
}

/// Emulates lightweight server verification endpoints completing hash storage.
fn server_thread(rx: mpsc::Receiver<ClientPayload>, response_tx: mpsc::SyncSender<ServerResponse>) {
    let ClientPayload {
        blockhash_bytes,
        salt,
        params,
    } = rx.recv().unwrap();

    let output_len = params.output_len().unwrap_or(32);
    let mut output_bytes = vec![0u8; output_len];
    blake2b_long(&[&blockhash_bytes], &mut output_bytes);

    let salt_ref = argon2::password_hash::Salt::from_b64(salt.as_str()).unwrap();
    let hash = argon2::password_hash::Output::new(&output_bytes).unwrap();

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
