#!/bin/bash
# Test script to verify default parameters work correctly

set -e

echo "Testing default sequence bits parameter..."

# Build the project
echo "Building..."
cargo build --release > /dev/null 2>&1

# Run with defaults and capture output
echo "Running with default parameters..."
OUTPUT=$(timeout 1 ./target/release/sha-yest --seed 42 2>&1 || true)

# Check for correct sequence bits in output
if echo "$OUTPUT" | grep -q "Sequence bits: 256"; then
    echo "✓ PASS: Configuration shows 256 bits"
else
    echo "✗ FAIL: Configuration does not show 256 bits"
    echo "$OUTPUT"
    exit 1
fi

if echo "$OUTPUT" | grep -q "Generated random 256-bit sequence:"; then
    echo "✓ PASS: Output shows 256-bit sequence"
else
    echo "✗ FAIL: Output does not show 256-bit sequence"
    echo "$OUTPUT"
    exit 1
fi

# Make sure it's NOT showing 512
if echo "$OUTPUT" | grep -q "512-bit sequence"; then
    echo "✗ FAIL: Output incorrectly shows 512-bit sequence"
    echo "$OUTPUT"
    exit 1
else
    echo "✓ PASS: Output does not incorrectly show 512-bit sequence"
fi

echo ""
echo "All tests passed! Default parameters correctly use 256 bits."
