# Argon2 Server Relief Demo

A proof-of-concept Rust implementation demonstrating **Server-Relief Password Hashing** using Argon2id. 

This architecture shifts the high memory and CPU cost of running memory-hard functions (MHFs) from the authentication server to the untrusted client, without exposing the raw password or sacrificing the cryptographic guarantees of the password storage format.

## The Problem & The Solution

When an application handles millions of concurrent authentication or registration requests, running a resource-heavy algorithm like Argon2id on the server creates an easy vector for **Denial of Service (DoS)** attacks. An attacker can flood the endpoint with registration requests, exhausting the server's CPU and memory capacity.

**Server-Relief** solves this by dividing Argon2id into two distinct phases:

1. **Client Phase (Memory-Hard):** The client generates a random salt, allocates the matrix space, computes the entire time/memory cost steps, and extracts the final internal block state.
2. **Server Phase (Finalization):** The client sends only the tiny, XOR-folded final memory block over the wire. The server performs a cheap, lightweight pseudo-random hash transformation (BLAKE2b) on this payload to produce the final verifiable password hash string.

This repo simulates this client-server boundary using dedicated threads and synchronous `mpsc` channels to model a standard API network request/response lifecycle.
