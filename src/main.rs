use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint16, PublicKey};
use tfhe::prelude::*;
use std::io::{self, Write};
use rayon::prelude::*;
use std::time::Instant;

/// Maximum supported index for 16-bit Fibonacci; `F(25) = 75025` > `u16::MAX`.
const MAX_FIBONACCI_INDEX: u16 = 24;

/// Read a `u16` in the range `0..=24` from stdin.
///
/// Returns a `ParseIntError` if parsing fails; the caller is expected to retry.
fn get_number_input() -> io::Result<u16> {
    print!("Enter a number (0-{}): ", MAX_FIBONACCI_INDEX);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    input
        .trim()
        .parse::<u16>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Iterative homomorphic additions with encrypted index-selection.
/// Builds encrypted indices internally, then iterates with homomorphic additions.
fn fibonacci_additions(n: &FheUint16, pks: &PublicKey) -> FheUint16 {
    let encrypted_indices = build_encrypted_indices(pks);

    // Initialize result with F(0) or F(1) depending on whether n == 0.
    let n_is_0 = n.eq(&encrypted_indices[0]);
    let mut a = encrypted_indices[0].clone();
    let mut b = encrypted_indices[1].clone();
    let mut result = n_is_0.select(&a, &b);

    for i in 2..=MAX_FIBONACCI_INDEX {
        let next_fib = a + b.clone();
        a = b;
        b = next_fib.clone();
        let i_encrypted = encrypted_indices[usize::from(i)].clone();
        let n_is_i = n.eq(&i_encrypted);
        // Use encrypted equality + select to multiplex the running result
        // without data-dependent control flow.
        result = n_is_i.select(&next_fib,&result);
    }

    result
}

/// Build a plaintext Fibonacci table up to MAX_FIBONACCI_INDEX.
fn build_fibonacci_table_plain() -> Vec<u16> {
    let mut fibs = Vec::with_capacity(usize::from(MAX_FIBONACCI_INDEX) + 1);
    let mut a: u16 = 0;
    let mut b: u16 = 1;
    fibs.push(a);
    for _ in 1..=MAX_FIBONACCI_INDEX {
        // invariant: a = F(k), b = F(k+1)
        fibs.push(b);
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    fibs
}

/// Build encrypted indices with parallelization.
fn build_encrypted_indices(pks: &PublicKey) -> Vec<FheUint16> {
    (0..=MAX_FIBONACCI_INDEX)
        .into_par_iter()
        .map(|i| FheUint16::encrypt(i, pks))
        .collect()
}

/// Build encrypted Fibonacci table from plaintext with parallelization.
fn build_encrypted_fibs(pks: &PublicKey) -> Vec<FheUint16> {
    let fibs_plain = build_fibonacci_table_plain();
    fibs_plain
        .par_iter()
        .copied()
        .map(|v| FheUint16::encrypt(v, pks))
        .collect()
}

/// Lookup over an encrypted table
/// equality + select, reusing prebuilt tables.
fn fibonacci_lookup_with_tables(
    n: &FheUint16,
    encrypted_indices: &[FheUint16],
    encrypted_fibs: &[FheUint16],
) -> FheUint16 {
    let mut result = encrypted_fibs[0].clone();
    for i in 1..=usize::from(MAX_FIBONACCI_INDEX) {
        let is_match = n.eq(&encrypted_indices[i]);
        result = is_match.select(&encrypted_fibs[i], &result);
    }
    result
}

/// Plaintext reference implementation used for verification.
fn fibonacci_plaintext(n: u16) -> u16 {
    let mut a = 0;
    let mut b = 1;
    for _ in 0..n {
        let tmp = a + b;
        a = b;
        b = tmp;
    }
    a
}

fn main() {
    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);
    let pks = PublicKey::new(&client_key);

    // Get user input for the first number
    let clear_a = loop {
        match get_number_input() {
            Ok(num) => break num,
            Err(_) => println!("Invalid input. Please enter a number between 0 and 24."),
        }
    };
    println!("You entered: {}", clear_a);
    let a = FheUint16::encrypt(clear_a, &client_key);

    // Server-side
    set_server_key(server_key);
    println!("Computing Fibonacci with two strategies...");

    // One-time setup (parallelizable, public-key side)
    let t_setup_start = Instant::now();
    let encrypted_indices = build_encrypted_indices(&pks);
    let encrypted_fibs = build_encrypted_fibs(&pks);
    let dur_setup = t_setup_start.elapsed();

    // One-shot baseline: additions (builds indices internally)
    let t_add_total = Instant::now();
    let result_add = fibonacci_additions(&a, &pks);
    let dur_add_total = t_add_total.elapsed();

    let t_lt_compute = Instant::now();
    let result_lt = fibonacci_lookup_with_tables(&a, &encrypted_indices, &encrypted_fibs);
    let dur_lt_compute = t_lt_compute.elapsed();

    // Client-side
    let decrypted_add: u16 = result_add.decrypt(&client_key);
    let decrypted_lt: u16 = result_lt.decrypt(&client_key);
    let expected = fibonacci_plaintext(clear_a);

    println!("Additions: {} ms, result {}", dur_add_total.as_millis(), decrypted_add);
    println!("Setup (lookup tables): {} ms", dur_setup.as_millis());
    println!("Lookup (uses setup): compute-only: {} ms, result {}", dur_lt_compute.as_millis(), decrypted_lt);
    println!("Expected: {}", expected);
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_fibonacci() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        let pks = PublicKey::new(&client_key);

        set_server_key(server_key);

        // Test for a range of small n
        for n in 0u16..=10 {
            let encrypted = FheUint16::encrypt(n, &client_key);
            let enc_add = fibonacci_additions(&encrypted, &pks);
            let encrypted_indices = build_encrypted_indices(&pks);
            let encrypted_fibs = build_encrypted_fibs(&pks);
            let enc_lt = fibonacci_lookup_with_tables(&encrypted, &encrypted_indices, &encrypted_fibs);
            let dec_add: u16 = enc_add.decrypt(&client_key);
            let dec_lt: u16 = enc_lt.decrypt(&client_key);

            let expected = fibonacci_plaintext(n);

            assert_eq!(
                dec_add, expected,
                "Additions mismatch for n = {}: encrypted = {}, plaintext = {}",
                n, dec_add, expected
            );
            assert_eq!(
                dec_lt, expected,
                "Lookup mismatch for n = {}: encrypted = {}, plaintext = {}",
                n, dec_lt, expected
            );
        }
    }
}
