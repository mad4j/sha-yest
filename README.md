# sha-yest

Testing SHA related stuff

## SHA-YEST: SHA Zero-Bit Search

This Rust program searches for SHA hashes that, when XORed with a random sequence, produce the maximum number of zero bits. It supports both SHA256 and SHA512 algorithms.

### Algorithm

1. Generates a random sequence (256 bits for SHA256, 512 bits for SHA512)
2. For each index from 0 to 2^index_bits iterations:
   - Calculates SHA hash of the index
   - Performs XOR between the SHA hash and the random sequence
   - Counts the number of zero bits in the XOR result
3. Stops early if:
   - All bits are zero (perfect match)
   - The number of zeros meets or exceeds the configurable threshold
4. Otherwise returns the SHA hash that generated the most zeros

### Usage

Build the project:
```bash
cargo build --release
```

Run with default parameters (SHA256, 2^16 iterations, threshold 200):
```bash
cargo run --release
```

Run with custom parameters:
```bash
# Use SHA512 with 2^12 iterations and threshold of 300
cargo run --release -- --sequence-bits 512 --index-bits 12 --threshold 300

# Use SHA256 with 2^8 iterations and threshold of 150
cargo run --release -- --sequence-bits 256 --index-bits 8 --threshold 150

# Short form
cargo run --release -- -s 512 -i 12 -t 300
```

View help:
```bash
cargo run --release -- --help
```

### Command-Line Options

- `-s, --sequence-bits <BITS>` - Number of bits in the initial sequence (256 or 512, determines SHA algorithm) [default: 256]
- `-i, --index-bits <BITS>` - Number of bits for the search index (determines iteration count: 2^index_bits, must be 1-32) [default: 16]
- `-t, --threshold <VALUE>` - Threshold value for zeros (early stop if reached) [default: 200]

### Output

The program displays:
- The configuration (SHA algorithm, number of iterations, threshold)
- The generated random sequence
- Progress updates showing new best results
- The final result with:
  - Index value that produced the best result
  - Number of zero bits found
  - The SHA hash value

### Example

```
SHA-YEST: Searching for SHA256 hashes with maximum zero bits after XOR
Configuration:
  Sequence bits: 256 (using SHA256)
  Index bits: 16 (2^16 = 65536 iterations)
  Threshold: 200 zeros out of 256 bits

Generated random 256-bit sequence:
ca836c7c0a9c2c5fb8f1b96b249ff36b659abf8df0a510bd5338a15aad6cd559

New best at index 0: 143 zeros
  Hash: df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
  XOR:  154757e40e055da4f8e6c8be99605b2e6c17b3512fae01fc97e0b3fdb3a7c440
  ...

Search complete!
Best result:
  Index: 3326
  Zeros: 163 out of 256 bits
  Hash: 89cad95cca1dbd178a66bd57d999f35c61abf53dad2d506d4359f21b5f560553
```

### Dependencies

- `sha2` - SHA-2 hash functions (SHA256 and SHA512)
- `rand` - Random number generation
- `clap` - Command-line argument parsing
