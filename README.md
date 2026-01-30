# sha-yest

Testing SHA related stuff

## SHA-YEST: SHA256 Zero-Bit Search

This Rust program searches for SHA256 hashes that, when XORed with a random 256-bit sequence, produce the maximum number of zero bits.

### Algorithm

1. Generates a random 256-bit (32 bytes) sequence
2. For each index from 0 to 65535 (2^16 iterations):
   - Calculates SHA256 of the index
   - Performs XOR between the SHA256 hash and the random sequence
   - Counts the number of zero bits in the XOR result
3. Stops early if:
   - All 256 bits are zero (perfect match)
   - The number of zeros meets or exceeds a configurable threshold
4. Otherwise returns the SHA256 hash that generated the most zeros

### Usage

Build the project:
```bash
cargo build --release
```

Run with default threshold (200 zeros out of 256 bits):
```bash
cargo run --release
```

Run with custom threshold (e.g., 180 zeros):
```bash
cargo run --release -- 180
```

### Output

The program displays:
- The generated random 256-bit sequence
- Progress updates showing new best results
- The final result with:
  - Index value that produced the best result
  - Number of zero bits found (out of 256 bits from SHA256)
  - The SHA256 hash value

### Example

```
SHA-YEST: Searching for SHA256 hashes with maximum zero bits after XOR
Threshold: 200 zeros out of 256 bits

Generated random 256-bit sequence:
ca836c7c0a9c2c5fb8f1b96b249ff36b659abf8df0a510bd5338a15aad6cd559

New best at index 0: 143 zeros
  Hash: df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
  ...

Search complete!
Best result:
  Index: 3326
  Zeros: 163 out of 256 bits
  Hash: 89cad95cca1dbd178a66bd57d999f35c61abf53dad2d506d4359f21b5f560553
```

### Dependencies

- `sha2` - SHA-2 hash functions
- `rand` - Random number generation
