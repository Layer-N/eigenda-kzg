//! Simple script for benchmarking cycle count on 64KiB.

use sp1_sdk::{ProverClient, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    sp1_sdk::utils::setup_logger();

    let mut rng = rand_pcg::Pcg64Mcg::new(0);
    let input = (0..(1 << 20))
        .map(|_| rand::Rng::gen::<u8>(&mut rng))
        .collect::<Vec<_>>();
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    let client = ProverClient::new();
    let (pub_vals, report) = client.execute(ELF, stdin).expect("execution failed");

    println!("public values: {:?}", pub_vals);
    println!("report: {:?}", report);

    let result: [u8; 64] = pub_vals.as_slice().try_into().unwrap();
    let expected = eigenda_kzg::commit(&input).unwrap();
    assert_eq!(result, expected);
}
