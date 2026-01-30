use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use clap::Parser;

/// SHA-YEST: Search for SHA hashes with maximum zero bits after XOR
#[derive(Parser, Debug)]
#[command(name = "sha-yest")]
#[command(about = "Searches for SHA hashes with maximum zero bits after XOR", long_about = None)]
struct Args {
    /// Number of bits in the initial sequence (256 or 512, determines SHA algorithm)
    #[arg(short = 's', long, default_value_t = 256, value_parser = clap::value_parser!(u16).range(1..))]
    sequence_bits: u16,

    /// Number of bits for the search index (determines iteration count: 2^index_bits)
    #[arg(short = 'i', long, default_value_t = 16, value_parser = clap::value_parser!(u8).range(1..=32))]
    index_bits: u8,

    /// Threshold value for zeros (early stop if reached)
    #[arg(short = 't', long, default_value_t = 200)]
    threshold: usize,
}

/// Counts the number of zero bits in a byte array
fn count_zeros(data: &[u8]) -> usize {
    data.iter().map(|byte| byte.count_zeros() as usize).sum()
}

/// Performs XOR between two byte arrays of the same length
fn xor_arrays(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn main() {
    let args = Args::parse();

    // Validate sequence_bits (must be 256 or 512)
    if args.sequence_bits != 256 && args.sequence_bits != 512 {
        eprintln!("Error: sequence_bits must be 256 or 512. Got: {}", args.sequence_bits);
        std::process::exit(1);
    }

    // index_bits is already validated by clap (1-32 range)
    let index_bits = args.index_bits;

    // Validate and adjust threshold if needed
    let threshold = if args.threshold > args.sequence_bits as usize {
        eprintln!("Warning: Threshold {} exceeds maximum {} bits. Using {}.", 
                  args.threshold, args.sequence_bits, args.sequence_bits);
        args.sequence_bits as usize
    } else {
        args.threshold
    };

    let sha_algorithm = if args.sequence_bits == 256 { "SHA256" } else { "SHA512" };
    let max_iterations = 1u64 << index_bits;
    
    println!("SHA-YEST: Searching for {} hashes with maximum zero bits after XOR", sha_algorithm);
    println!("Configuration:");
    println!("  Sequence bits: {} (using {})", args.sequence_bits, sha_algorithm);
    println!("  Index bits: {} (2^{} = {} iterations)", index_bits, index_bits, max_iterations);
    println!("  Threshold: {} zeros out of {} bits", threshold, args.sequence_bits);
    println!();

    // Generate random sequence based on sequence_bits
    let mut rng = rand::thread_rng();
    let sequence_bytes = (args.sequence_bits / 8) as usize;
    let random_sequence: Vec<u8> = (0..sequence_bytes).map(|_| rng.gen::<u8>()).collect();
    
    println!("Generated random {}-bit sequence:", args.sequence_bits);
    println!("{}", hex_encode(&random_sequence));
    println!();

    // Call appropriate search function based on sequence_bits
    if args.sequence_bits == 256 {
        search_sha256(&random_sequence, max_iterations, threshold);
    } else {
        search_sha512(&random_sequence, max_iterations, threshold);
    }
}

/// Helper function to encode bytes as hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Search using SHA256
fn search_sha256(random_sequence: &[u8], max_iterations: u64, threshold: usize) {
    let mut best_index: u64 = 0;
    let mut best_zeros: usize = 0;
    let mut best_hash: Vec<u8> = vec![];
    let total_bits = 256;

    for i in 0..max_iterations {
        // Calculate SHA256 of the index
        let mut hasher = Sha256::new();
        hasher.update(i.to_le_bytes());
        let hash = hasher.finalize();
        
        // XOR with random sequence
        let xor_result = xor_arrays(&hash, random_sequence);
        
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
        
        // Stop if all zeros
        if zeros == total_bits {
            println!();
            println!("Perfect match found! All {} bits are zero.", total_bits);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(&hash));
            return;
        }
        
        // Stop if threshold met or exceeded
        if zeros >= threshold {
            println!();
            println!("Threshold met or exceeded! Found {} zeros (threshold: {})", zeros, threshold);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(&hash));
            return;
        }
        
        // Print progress every 10000 iterations
        if i % 10000 == 0 && i > 0 {
            println!("Progress: {} / {} iterations completed...", i, max_iterations);
        }
    }

    // Print final result
    println!();
    println!("Search complete!");
    println!("Best result:");
    println!("  Index: {}", best_index);
    println!("  Zeros: {} out of {} bits", best_zeros, total_bits);
    println!("  Hash: {}", hex_encode(&best_hash));
}

/// Search using SHA512
fn search_sha512(random_sequence: &[u8], max_iterations: u64, threshold: usize) {
    let mut best_index: u64 = 0;
    let mut best_zeros: usize = 0;
    let mut best_hash: Vec<u8> = vec![];
    let total_bits = 512;

    for i in 0..max_iterations {
        // Calculate SHA512 of the index
        let mut hasher = Sha512::new();
        hasher.update(i.to_le_bytes());
        let hash = hasher.finalize();
        
        // XOR with random sequence
        let xor_result = xor_arrays(&hash, random_sequence);
        
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
        
        // Stop if all zeros
        if zeros == total_bits {
            println!();
            println!("Perfect match found! All {} bits are zero.", total_bits);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(&hash));
            return;
        }
        
        // Stop if threshold met or exceeded
        if zeros >= threshold {
            println!();
            println!("Threshold met or exceeded! Found {} zeros (threshold: {})", zeros, threshold);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(&hash));
            return;
        }
        
        // Print progress every 10000 iterations
        if i % 10000 == 0 && i > 0 {
            println!("Progress: {} / {} iterations completed...", i, max_iterations);
        }
    }

    // Print final result
    println!();
    println!("Search complete!");
    println!("Best result:");
    println!("  Index: {}", best_index);
    println!("  Zeros: {} out of {} bits", best_zeros, total_bits);
    println!("  Hash: {}", hex_encode(&best_hash));
}
