use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256, Sha512};
use clap::{Parser, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopReason {
    Exhausted,
    ThresholdReached,
    PerfectMatch,
}

#[derive(Debug, Clone)]
struct SearchResult {
    total_bits: u16,
    threshold: usize,
    stop_reason: StopReason,
    best_index: u64,
    best_zeros: usize,
    best_hash: Vec<u8>,
}

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
    #[arg(short = 'i', long, default_value_t = 16, value_parser = clap::value_parser!(u8).range(1..=64))]
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

    // index_bits is validated by clap (1-64 range)
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

    // Compute 2^index_bits safely. We iterate using u64 indices, so we must be able to
    // represent the iteration count as u64.
    let requested_iterations: u128 = 1u128 << index_bits;
    if requested_iterations > u64::MAX as u128 {
        eprintln!(
            "Error: index-bits={} would require 2^{} iterations ({}), which exceeds u64::MAX ({}).\n\
Choose an index-bits value <= 63.",
            index_bits,
            index_bits,
            requested_iterations,
            u64::MAX
        );
        std::process::exit(2);
    }
    let max_iterations = requested_iterations as u64;
    
    println!("SHA-YEST: Searching for {} hashes with maximum zero bits after XOR", sha_algorithm);
    println!("Configuration:");
    println!("  Sequence bits: {} (using {})", sequence_bits, sha_algorithm);
    println!(
        "  Index bits: {} (2^{} = {} iterations)",
        index_bits, index_bits, requested_iterations
    );
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

    // Create a progress bar in main so reporting stays centralized.
    let pb_label = match args.sequence_bits {
        SequenceBits::Bits128 => "SHA256/128",
        SequenceBits::Bits256 => "SHA256",
        SequenceBits::Bits512 => "SHA512",
    };
    let pb = create_progress_bar(max_iterations, pb_label);

    // Call appropriate search function based on sequence_bits.
    // Consistent rule: sequence_bits <= 256 => SHA256 (truncated if needed), sequence_bits > 256 => SHA512.
    let result = match args.sequence_bits {
        SequenceBits::Bits128 => search_sha256_128(&random_sequence, max_iterations, threshold, &pb),
        SequenceBits::Bits256 => search_sha256(&random_sequence, max_iterations, threshold, &pb),
        SequenceBits::Bits512 => search_sha512(&random_sequence, max_iterations, threshold, &pb),
    };

    let finish_msg = match result.stop_reason {
        StopReason::PerfectMatch => "perfect match".to_string(),
        StopReason::ThresholdReached => format!("threshold reached (best={})", result.best_zeros),
        StopReason::Exhausted => format!("done (best={})", result.best_zeros),
    };
    pb.finish_with_message(finish_msg);

    println!();
    print_final_report(&result, &random_sequence);
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

fn print_final_report(result: &SearchResult, random_sequence: &[u8]) {
    match result.stop_reason {
        StopReason::PerfectMatch => {
            println!("Perfect match found! All {} bits are zero.", result.total_bits);
        }
        StopReason::ThresholdReached => {
            println!(
                "Threshold reached! Best zeros: {} (threshold: {})",
                result.best_zeros, result.threshold
            );
        }
        StopReason::Exhausted => {
            println!("Search complete!");
        }
    }

    println!("Best result:");
    println!("  Index: {}", result.best_index);
    println!("  Zeros: {} out of {} bits", result.best_zeros, result.total_bits);
    println!("  Hash: {}", hex_encode(&result.best_hash));

    let base_zeros = count_zeros(random_sequence);
    let enhancement = result.best_zeros as isize - base_zeros as isize;
    println!(
        "  Enhancement vs original sequence: {:+} zero bits (original: {} / {})",
        enhancement, base_zeros, result.total_bits
    );
}

/// Search using SHA256 (128 bits)
fn search_sha256_128(
    random_sequence: &[u8],
    max_iterations: u64,
    threshold: usize,
    pb: &ProgressBar,
) -> SearchResult {
    let total_bits: u16 = 128;
    pb.set_message("best=0".to_string());

    let stop_reason = AtomicU8::new(0); // 0=none, 1=threshold, 2=perfect
    let best_zeros = AtomicUsize::new(0);
    let best = Mutex::new((0u64, 0usize, Vec::<u8>::new()));

    let _ = (0..max_iterations).into_par_iter().try_for_each(|i| -> Result<(), ()> {
        if stop_reason.load(Ordering::Relaxed) != 0 {
            return Err(());
        }

        // Calculate SHA256 of the index, then use only first 128 bits (16 bytes)
        let mut hasher = Sha256::new();
        hasher.update(i.to_le_bytes());
        let full_hash = hasher.finalize();
        let hash = &full_hash[..16];

        // XOR with random sequence
        let xor_result = xor_arrays(hash, random_sequence);

        // Count zeros in the XOR result
        let zeros = count_zeros(&xor_result);

        pb.inc(1);

        // Update best result (atomic gate + mutex for hash storage)
        let mut current_best = best_zeros.load(Ordering::Relaxed);
        while zeros > current_best {
            match best_zeros.compare_exchange_weak(
                current_best,
                zeros,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    if let Ok(mut guard) = best.lock() {
                        *guard = (i, zeros, hash.to_vec());
                    }
                    pb.set_message(format!("best={}", zeros));
                    break;
                }
                Err(updated) => current_best = updated,
            }
        }

        // Stop if all zeros
        if zeros as u16 == total_bits {
            stop_reason.store(2, Ordering::Relaxed);
            return Err(());
        }

        // Stop if the best reached or exceeded threshold (more robust than stopping on any single hit)
        if best_zeros.load(Ordering::Relaxed) >= threshold {
            stop_reason.store(1, Ordering::Relaxed);
            return Err(());
        }

        Ok(())
    });

    let (best_index, best_zeros_val, best_hash) = match best.into_inner() {
        Ok(v) => v,
        Err(poisoned) => poisoned.into_inner(),
    };

    let reason = match stop_reason.load(Ordering::Relaxed) {
        2 => StopReason::PerfectMatch,
        1 => StopReason::ThresholdReached,
        _ => StopReason::Exhausted,
    };

    SearchResult {
        total_bits,
        threshold,
        stop_reason: reason,
        best_index,
        best_zeros: best_zeros_val,
        best_hash,
    }
}

/// Search using SHA256
fn search_sha256(
    random_sequence: &[u8],
    max_iterations: u64,
    threshold: usize,
    pb: &ProgressBar,
) -> SearchResult {
    let total_bits: u16 = 256;
    pb.set_message("best=0".to_string());

    let stop_reason = AtomicU8::new(0); // 0=none, 1=threshold, 2=perfect
    let best_zeros = AtomicUsize::new(0);
    let best = Mutex::new((0u64, 0usize, Vec::<u8>::new()));

    let _ = (0..max_iterations).into_par_iter().try_for_each(|i| -> Result<(), ()> {
        if stop_reason.load(Ordering::Relaxed) != 0 {
            return Err(());
        }

        // Calculate SHA256 of the index
        let mut hasher = Sha256::new();
        hasher.update(i.to_le_bytes());
        let hash = hasher.finalize();

        // XOR with random sequence
        let xor_result = xor_arrays(&hash, random_sequence);

        // Count zeros in the XOR result
        let zeros = count_zeros(&xor_result);

        pb.inc(1);

        // Update best result (atomic gate + mutex for hash storage)
        let mut current_best = best_zeros.load(Ordering::Relaxed);
        while zeros > current_best {
            match best_zeros.compare_exchange_weak(
                current_best,
                zeros,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    if let Ok(mut guard) = best.lock() {
                        *guard = (i, zeros, hash.to_vec());
                    }
                    pb.set_message(format!("best={}", zeros));
                    break;
                }
                Err(updated) => current_best = updated,
            }
        }

        // Stop if all zeros
        if zeros as u16 == total_bits {
            stop_reason.store(2, Ordering::Relaxed);
            return Err(());
        }

        // Stop if the best reached or exceeded threshold
        if best_zeros.load(Ordering::Relaxed) >= threshold {
            stop_reason.store(1, Ordering::Relaxed);
            return Err(());
        }

        Ok(())
    });

    let (best_index, best_zeros_val, best_hash) = match best.into_inner() {
        Ok(v) => v,
        Err(poisoned) => poisoned.into_inner(),
    };

    let reason = match stop_reason.load(Ordering::Relaxed) {
        2 => StopReason::PerfectMatch,
        1 => StopReason::ThresholdReached,
        _ => StopReason::Exhausted,
    };

    SearchResult {
        total_bits,
        threshold,
        stop_reason: reason,
        best_index,
        best_zeros: best_zeros_val,
        best_hash,
    }
}

/// Search using SHA512
fn search_sha512(
    random_sequence: &[u8],
    max_iterations: u64,
    threshold: usize,
    pb: &ProgressBar,
) -> SearchResult {
    let total_bits: u16 = 512;
    pb.set_message("best=0".to_string());

    let stop_reason = AtomicU8::new(0); // 0=none, 1=threshold, 2=perfect
    let best_zeros = AtomicUsize::new(0);
    let best = Mutex::new((0u64, 0usize, Vec::<u8>::new()));

    let _ = (0..max_iterations).into_par_iter().try_for_each(|i| -> Result<(), ()> {
        if stop_reason.load(Ordering::Relaxed) != 0 {
            return Err(());
        }

        // Calculate SHA512 of the index
        let mut hasher = Sha512::new();
        hasher.update(i.to_le_bytes());
        let hash = hasher.finalize();

        // XOR with random sequence
        let xor_result = xor_arrays(&hash, random_sequence);

        // Count zeros in the XOR result
        let zeros = count_zeros(&xor_result);

        pb.inc(1);

        // Update best result (atomic gate + mutex for hash storage)
        let mut current_best = best_zeros.load(Ordering::Relaxed);
        while zeros > current_best {
            match best_zeros.compare_exchange_weak(
                current_best,
                zeros,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    if let Ok(mut guard) = best.lock() {
                        *guard = (i, zeros, hash.to_vec());
                    }
                    pb.set_message(format!("best={}", zeros));
                    break;
                }
                Err(updated) => current_best = updated,
            }
        }

        // Stop if all zeros
        if zeros as u16 == total_bits {
            stop_reason.store(2, Ordering::Relaxed);
            return Err(());
        }

        // Stop if the best reached or exceeded threshold
        if best_zeros.load(Ordering::Relaxed) >= threshold {
            stop_reason.store(1, Ordering::Relaxed);
            return Err(());
        }

        Ok(())
    });

    let (best_index, best_zeros_val, best_hash) = match best.into_inner() {
        Ok(v) => v,
        Err(poisoned) => poisoned.into_inner(),
    };

    let reason = match stop_reason.load(Ordering::Relaxed) {
        2 => StopReason::PerfectMatch,
        1 => StopReason::ThresholdReached,
        _ => StopReason::Exhausted,
    };

    SearchResult {
        total_bits,
        threshold,
        stop_reason: reason,
        best_index,
        best_zeros: best_zeros_val,
        best_hash,
    }
}
