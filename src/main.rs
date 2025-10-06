use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint16, PublicKey};
use tfhe::prelude::*;
use std::io::{self, Write};
use rayon::prelude::*;

// 24 is the maximum index for the Fibonacci sequence that can be computed with a 16-bit integer
const MAX_FIBONACCI_INDEX: u16 = 10;

fn get_number_input() -> Result<u16, std::num::ParseIntError> {
    print!("Enter a number (0-10): ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    input.trim().parse::<u16>()
}

fn fibonacci(n: FheUint16, pks: PublicKey) -> FheUint16 {
    // Precompute encrypted indices in parallel
    println!("Precomputing encrypted indices...");
    let encrypted_indices = (0..=MAX_FIBONACCI_INDEX)
        .into_par_iter()
        .map(|i| FheUint16::encrypt(i, &pks))
        .collect::<Vec<FheUint16>>();

    println!("n_is_0");
    let n_is_0 = n.eq(&encrypted_indices[0]);
    println!("selecting result");
    let mut result = n_is_0.select(&encrypted_indices[0], &encrypted_indices[1]);

    let mut a = encrypted_indices[0].clone();
    let mut b = encrypted_indices[1].clone();

    for i in 2..=MAX_FIBONACCI_INDEX {
        println!("Calculating next Fibonacci number...");
        let next_fib = a + b.clone();
        a = b;
        b = next_fib.clone();
        println!("Encrypting index...");
        let i_usize = i.clone() as usize;
        let i_encrypted = encrypted_indices[i_usize].clone();
        println!("Checking if input is equal to index...");
        let n_is_i = n.eq(&i_encrypted);
        println!("Selecting result...");
        result = n_is_i.select(&next_fib,&result);
    }

    return result;
}

fn fibonacci_plaintext(n: u16) -> u16 {
    let mut a = 0;
    let mut b = 1;
    for _ in 0..n {
        let tmp = a + b;
        a = b;
        b = tmp;
    }
    return a;
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
            Err(_) => println!("Invalid input. Please enter a number between 0 and 10."),
        }
    };

    println!("You entered: {}", clear_a);

    println!("Encrypting value...");
    let a = FheUint16::encrypt(clear_a, &client_key);

    // Server-side
    set_server_key(server_key);

    println!("Computing Fibonacci number...");
    let result = fibonacci(a, pks);

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
            let encrypted_result = fibonacci(encrypted, pks.clone());
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
