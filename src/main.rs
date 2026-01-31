use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256, Sha512};
use clap::{Parser, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Sequence length in bits
#[derive(Debug, Clone, Copy, ValueEnum)]
enum SequenceBits {
    #[value(name = "128")]
    Bits128,
    #[value(name = "256")]
    Bits256,
    #[value(name = "512")]
    Bits512,
}

impl SequenceBits {
    fn as_u16(&self) -> u16 {
        match self {
            SequenceBits::Bits128 => 128,
            SequenceBits::Bits256 => 256,
            SequenceBits::Bits512 => 512,
        }
    }
}

impl Default for SequenceBits {
    fn default() -> Self {
        SequenceBits::Bits256
    }
}

/// SHA-YEST: Search for SHA hashes with maximum zero bits after XOR
#[derive(Parser, Debug)]
#[command(name = "sha-yest")]
#[command(about = "Searches for SHA hashes with maximum zero bits after XOR", long_about = None)]
struct Args {
    /// Number of bits in the initial sequence (128, 256, or 512)
    #[arg(short = 's', long, default_value = "256")]
    sequence_bits: SequenceBits,

    /// Number of bits for the search index (determines iteration count: 2^index_bits)
    #[arg(short = 'i', long, default_value_t = 16, value_parser = clap::value_parser!(u8).range(1..=32))]
    index_bits: u8,

    /// Threshold value for zeros (early stop if reached)
    #[arg(short = 't', long, default_value_t = 200)]
    threshold: usize,

    /// Seed for PRNG initialization (optional, for reproducible random sequences)
    #[arg(long)]
    seed: Option<u64>,
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

    let sequence_bits = args.sequence_bits.as_u16();

    // index_bits is already validated by clap (1-32 range)
    let index_bits = args.index_bits;

    // Validate and adjust threshold if needed
    let threshold = if args.threshold > sequence_bits as usize {
        eprintln!("Warning: Threshold {} exceeds maximum {} bits. Using {}.", 
                  args.threshold, sequence_bits, sequence_bits);
        sequence_bits as usize
    } else {
        args.threshold
    };

    // Determine SHA algorithm display string
    // Rule: sequence_bits <= 256 use SHA256, sequence_bits > 256 use SHA512
    let sha_algorithm = match args.sequence_bits {
        SequenceBits::Bits128 => "SHA256 (128 bits)", // 128 <= 256: use SHA256
        SequenceBits::Bits256 => "SHA256",              // 256 <= 256: use SHA256
        SequenceBits::Bits512 => "SHA512",              // 512 > 256: use SHA512
    };
    let max_iterations = 1u64 << index_bits;
    
    println!("SHA-YEST: Searching for {} hashes with maximum zero bits after XOR", sha_algorithm);
    println!("Configuration:");
    println!("  Sequence bits: {} (using {})", sequence_bits, sha_algorithm);
    println!("  Index bits: {} (2^{} = {} iterations)", index_bits, index_bits, max_iterations);
    println!("  Threshold: {} zeros out of {} bits", threshold, sequence_bits);
    if let Some(seed_value) = args.seed {
        println!("  Seed: {}", seed_value);
    }
    println!();

    // Generate random sequence based on sequence_bits, using seed if provided
    let sequence_bytes = (sequence_bits / 8) as usize;
    let random_sequence: Vec<u8> = if let Some(seed_value) = args.seed {
        let mut rng = ChaCha8Rng::seed_from_u64(seed_value);
        (0..sequence_bytes).map(|_| rng.gen::<u8>()).collect()
    } else {
        let mut rng = rand::thread_rng();
        (0..sequence_bytes).map(|_| rng.gen::<u8>()).collect()
    };
    
    println!("Generated random {}-bit sequence:", sequence_bits);
    println!("{}", hex_encode(&random_sequence));
    let sequence_zeros = count_zeros(&random_sequence);
    println!(
        "Zero bits in random sequence: {} out of {} bits",
        sequence_zeros, sequence_bits
    );
    println!();

    // Call appropriate search function based on sequence_bits
    // Consistent rule: The number of bits indicates the SHA type:
    //   sequence_bits <= 256: use SHA256 (truncated if needed)
    //   sequence_bits > 256: use SHA512
    match args.sequence_bits {
        SequenceBits::Bits128 => search_sha256_128(&random_sequence, max_iterations, threshold), // 128 <= 256: SHA256
        SequenceBits::Bits256 => search_sha256(&random_sequence, max_iterations, threshold),     // 256 <= 256: SHA256
        SequenceBits::Bits512 => search_sha512(&random_sequence, max_iterations, threshold),     // 512 > 256: SHA512
    }

    
}

/// Helper function to encode bytes as hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn create_progress_bar(max_iterations: u64, label: &str) -> ProgressBar {
    let pb = ProgressBar::new(max_iterations);
    let style = ProgressStyle::with_template(
        "{spinner:.green} {prefix} [{wide_bar:.cyan/blue}] {pos}/{len} ({per_sec}, eta {eta}) {msg}",
    )
    .unwrap()
    .progress_chars("=>-");

    pb.set_style(style);
    pb.set_prefix(label.to_string());
    pb.enable_steady_tick(Duration::from_millis(120));
    pb
}

/// Search using SHA256 (128 bits)
fn search_sha256_128(random_sequence: &[u8], max_iterations: u64, threshold: usize) {
    let mut best_index: u64 = 0;
    let mut best_zeros: usize = 0;
    let mut best_hash: Vec<u8> = vec![];
    let total_bits = 128;

    let pb = create_progress_bar(max_iterations, "SHA256/128");
    pb.set_message("best=0".to_string());

    for i in 0..max_iterations {
        pb.inc(1);
        // Calculate SHA256 of the index, then use only first 128 bits (16 bytes)
        let mut hasher = Sha256::new();
        hasher.update(i.to_le_bytes());
        let full_hash = hasher.finalize();
        let hash = &full_hash[..16];
        
        // XOR with random sequence
        let xor_result = xor_arrays(hash, random_sequence);
        
        // Count zeros in the XOR result
        let zeros = count_zeros(&xor_result);
        
        // Update best result
        if zeros > best_zeros {
            best_zeros = zeros;
            best_index = i;
            best_hash = hash.to_vec();
            
            pb.set_message(format!("best={}", best_zeros));
        }
        
        // Stop if all zeros
        if zeros == total_bits {
            pb.finish_with_message("perfect match".to_string());
            println!();
            println!("Perfect match found! All {} bits are zero.", total_bits);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(hash));
            return;
        }
        
        // Stop if threshold met or exceeded
        if zeros >= threshold {
            pb.finish_with_message("threshold reached".to_string());
            println!();
            println!("Threshold met or exceeded! Found {} zeros (threshold: {})", zeros, threshold);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(hash));
            return;
        }
    }

    // Print final result
    pb.finish_with_message(format!("done (best={})", best_zeros));
    println!();
    println!("Search complete!");
    println!("Best result:");
    println!("  Index: {}", best_index);
    println!("  Zeros: {} out of {} bits", best_zeros, total_bits);
    println!("  Hash: {}", hex_encode(&best_hash));
}

/// Search using SHA256
fn search_sha256(random_sequence: &[u8], max_iterations: u64, threshold: usize) {
    let mut best_index: u64 = 0;
    let mut best_zeros: usize = 0;
    let mut best_hash: Vec<u8> = vec![];
    let total_bits = 256;

    let pb = create_progress_bar(max_iterations, "SHA256");
    pb.set_message("best=0".to_string());

    for i in 0..max_iterations {
        pb.inc(1);
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
            
            pb.set_message(format!("best={}", best_zeros));
        }
        
        // Stop if all zeros
        if zeros == total_bits {
            pb.finish_with_message("perfect match".to_string());
            println!();
            println!("Perfect match found! All {} bits are zero.", total_bits);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(&hash));
            return;
        }
        
        // Stop if threshold met or exceeded
        if zeros >= threshold {
            pb.finish_with_message("threshold reached".to_string());
            println!();
            println!("Threshold met or exceeded! Found {} zeros (threshold: {})", zeros, threshold);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(&hash));
            return;
        }
    }

    // Print final result
    pb.finish_with_message(format!("done (best={})", best_zeros));
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

    let pb = create_progress_bar(max_iterations, "SHA512");
    pb.set_message("best=0".to_string());

    for i in 0..max_iterations {
        pb.inc(1);
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
            
            pb.set_message(format!("best={}", best_zeros));
        }
        
        // Stop if all zeros
        if zeros == total_bits {
            pb.finish_with_message("perfect match".to_string());
            println!();
            println!("Perfect match found! All {} bits are zero.", total_bits);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(&hash));
            return;
        }
        
        // Stop if threshold met or exceeded
        if zeros >= threshold {
            pb.finish_with_message("threshold reached".to_string());
            println!();
            println!("Threshold met or exceeded! Found {} zeros (threshold: {})", zeros, threshold);
            println!("Index: {}", i);
            println!("Hash: {}", hex_encode(&hash));
            return;
        }
    }

    // Print final result
    pb.finish_with_message(format!("done (best={})", best_zeros));
    println!();
    println!("Search complete!");
    println!("Best result:");
    println!("  Index: {}", best_index);
    println!("  Zeros: {} out of {} bits", best_zeros, total_bits);
    println!("  Hash: {}", hex_encode(&best_hash));
    // Show how much the best result improved zero-bits compared to the original random sequence
    let base_zeros = count_zeros(random_sequence);
    let enhancement = best_zeros as isize - base_zeros as isize;
    println!(
        "  Enhancement vs original sequence: {:+} zero bits (original: {} / {})",
        enhancement, base_zeros, total_bits
    );
}
