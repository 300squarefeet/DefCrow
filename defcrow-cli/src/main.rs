use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use std::io::{self, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("hash-password") => {
            print!("Enter password: ");
            io::stdout().flush().unwrap();
            let mut password = String::new();
            io::stdin().read_line(&mut password).expect("read failed");
            let password = password.trim();

            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .expect("hashing failed")
                .to_string();

            println!("{}", hash);
            println!("\nAdd to .env:");
            println!("DEFCROW_PASSWORD_HASH={}", hash);
        }
        _ => {
            eprintln!("Usage: defcrow-cli hash-password");
            std::process::exit(1);
        }
    }
}
