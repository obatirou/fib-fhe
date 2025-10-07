# FHE Fibonacci

## Run

```bash
cargo run --release
```

## Test

```bash
cargo test --release
```

## Implementation

This example implements two end-to-end strategies to compute `Fibonacci(n)`.

- **Additions**: Iterative homomorphic additions with encrypted equality-based selection. Best for a single query when you will not reuse any setup. See `fibonacci_additions`.

- **Lookup**: Build small encrypted tables once (indices and Fibonacci values) using the public key, then for each query use encrypted equality + `select` to pick the result. Compute-only time is low; best when you can reuse the setup across multiple queries. See: `build_encrypted_indices`, `build_encrypted_fibs`, and `fibonacci_lookup_with_tables`.

Lookup could be interesting for large values.
