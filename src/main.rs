use rand::Rng;
use sha2::{Digest, Sha256};
use std::env;

/// Counts the number of zero bits in a byte array
fn count_zeros(data: &[u8]) -> usize {
    data.iter().map(|byte| byte.count_zeros() as usize).sum()
}

/// Performs XOR between two byte arrays of the same length
fn xor_arrays(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn main() {
    // Parse threshold from command line argument or use default
    let args: Vec<String> = env::args().collect();
    let threshold: usize = if args.len() > 1 {
        match args[1].parse::<usize>() {
            Ok(val) if val <= 256 => val,
            Ok(val) => {
                eprintln!("Warning: Threshold {} exceeds maximum 256 bits. Using 256.", val);
                256
            }
            Err(_) => {
                eprintln!("Warning: Invalid threshold '{}'. Using default 200.", args[1]);
                200
            }
        }
    } else {
        200 // Default threshold (out of 256 bits from SHA256)
    };

    println!("SHA-YEST: Searching for SHA256 hashes with maximum zero bits after XOR");
    println!("Threshold: {} zeros out of 256 bits", threshold);
    println!();

    // Generate random 512-bit (64 bytes) sequence
    let mut rng = rand::thread_rng();
    let random_sequence: Vec<u8> = (0..64).map(|_| rng.gen::<u8>()).collect();
    
    println!("Generated random 512-bit sequence:");
    println!("{}", hex_encode(&random_sequence));
    println!();

    let mut best_index: u32 = 0;
    let mut best_zeros: usize = 0;
    let mut best_hash: Vec<u8> = vec![];

    // Search through indices from 0 to 2^16-1 (0 to 65535, total 65536 iterations)
    for i in 0..65536u32 {
        // Calculate SHA256 of the index
        let mut hasher = Sha256::new();
        hasher.update(i.to_le_bytes());
        let hash = hasher.finalize();
        
        // XOR with random sequence (use first 32 bytes of random sequence to match SHA256 output)
        let xor_result = xor_arrays(&hash, &random_sequence[..32]);
        
        // Count zeros in the XOR result
        let zeros = count_zeros(&xor_result);
        
        // Update best result
        if zeros > best_zeros {
            best_zeros = zeros;
            best_index = i;
            best_hash = hash.to_vec();
            
            println!("New best at index {}: {} zeros", i, zeros);
            println!("  Hash: {}", hex_encode(&best_hash));
            println!("  XOR:  {}", hex_encode(&xor_result));
        }
        
        // Stop if all zeros (256 bits)
        if zeros == 256 {
            println!();
            println!("Perfect match found! All 256 bits are zero.");
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(&hash));
            return;
        }
        
        // Stop if threshold exceeded
        if zeros >= threshold {
            println!();
            println!("Threshold exceeded! Found {} zeros (threshold: {})", zeros, threshold);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(&hash));
            return;
        }
        
        // Print progress every 10000 iterations
        if i % 10000 == 0 && i > 0 {
            println!("Progress: {} / 65536 iterations completed...", i);
        }
    }

    // Print final result
    println!();
    println!("Search complete!");
    println!("Best result:");
    println!("  Index: {}", best_index);
    println!("  Zeros: {} out of 256 bits", best_zeros);
    println!("  Hash: {}", hex_encode(&best_hash));
}

/// Helper function to encode bytes as hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
