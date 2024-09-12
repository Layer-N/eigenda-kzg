#![no_main]

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    println!("cycle-tracker-start: commit");
    let commit = eigenda_kzg::commit_delimited(&input).unwrap();
    println!("cycle-tracker-end: commit");
    sp1_zkvm::io::commit_slice(&commit);
}
