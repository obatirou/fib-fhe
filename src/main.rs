use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint16, PublicKey};
use tfhe::prelude::*;
use std::io::{self, Write};
use rayon::prelude::*;

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

/// Homomorphically compute `Fibonacci(n)`.
///
/// - `n`: encrypted index
/// - `pks`: public key derived from the same client key used to encrypt `n`;
///   used to encrypt constant indices.
///
/// Precondition: the server key must have been registered via `set_server_key`.
/// Returns an encrypted `F(n)`.
fn fibonacci(n: &FheUint16, pks: &PublicKey) -> FheUint16 {
    // Encrypt constants 0..=MAX in parallel to enable encrypted equality tests.
    let encrypted_indices : Vec<FheUint16> = (0..=MAX_FIBONACCI_INDEX)
        .into_par_iter()
        .map(|i| FheUint16::encrypt(i, pks))
        .collect();

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
    println!("Computing Fibonacci number...");
    let result = fibonacci(&a, &pks);

    // Client-side
    let decrypted_result: u16 = result.decrypt(&client_key);
    println!("Fibonacci decrypted for {} is {}", clear_a, decrypted_result);
    println!("Fibonacci clear for {} is {}", clear_a, fibonacci_plaintext(clear_a));
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
            let encrypted_result = fibonacci(&encrypted, &pks);
            let decrypted_result: u16 = encrypted_result.decrypt(&client_key);

            let expected = fibonacci_plaintext(n);

            assert_eq!(
                decrypted_result, expected,
                "Mismatch for n = {}: encrypted = {}, plaintext = {}",
                n, decrypted_result, expected
            );
        }
    }
}
