#![cfg(test)]

use rand::prelude::*;
use rayon::prelude::*;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn compute_native(payload: &[u8]) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    eigenda_kzg::commit(payload).map_err(Into::into)
}

fn compute_sp1(payload: &[u8]) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    sp1_sdk::utils::setup_logger();
    let mut stdin = sp1_sdk::SP1Stdin::new();
    stdin.write_slice(payload);
    let client = sp1_sdk::ProverClient::new();
    let (pub_vals, _report) = client.execute(ELF, stdin)?;
    Ok(pub_vals.as_slice().try_into().unwrap())
}

fn compute_eigenlib(payload: &[u8]) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    use ark_ec::AffineRepr;
    use ark_ff::{BigInteger, PrimeField};
    use std::sync::OnceLock;

    static MEMO: OnceLock<rust_kzg_bn254::kzg::Kzg> = OnceLock::new();
    let kzg = MEMO.get_or_init(|| {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("points");
        let g1 = root.join("g1.point");
        let g2 = root.join("g2.point.powerOf2");
        if !g1.exists() || !g2.exists() {
            panic!("`points/g1.point` or `points/g2.point.powerOf2` missing, see readme");
        }
        rust_kzg_bn254::kzg::Kzg::setup(
            g1.to_str().unwrap(),
            "",
            g2.to_str().unwrap(),
            268435456,
            131072,
        )
        .unwrap()
    });
    let poly = {
        let mut blob = rust_kzg_bn254::blob::Blob::new(payload.to_vec());
        blob.pad_data().unwrap();
        blob.to_polynomial(rust_kzg_bn254::polynomial::PolynomialFormat::InCoefficientForm)?
    };
    let c = kzg.commit(&poly)?;
    let Some((x, y)) = c.xy() else {
        return Ok([0; 64]);
    };
    let x = x.into_bigint().to_bytes_le();
    let y = y.into_bigint().to_bytes_le();
    Ok([x, y].concat().try_into().unwrap())
}

fn sample(rng: &mut impl rand::Rng, len: usize) -> Vec<u8> {
    // Trailing elements don't affect the commitment, so
    // randomly pad the input to ensure consistency among
    // the implementations for handling this.
    let split = match rng.gen_range(0..9) {
        0 => rng.gen_range(0..len),
        _ => len,
    };
    let mut buf = vec![0; len];
    for x in buf.iter_mut().take(split) {
        // Zeroes may have special behaviour, so sample
        // them with higher probability.
        *x = match rng.gen_range(0..4) {
            0 => 0,
            _ => rng.gen(),
        };
    }
    buf
}

#[test]
fn test_empty() {
    assert!(compute_native(&[]).is_err());
    assert!(compute_sp1(&[]).is_err());
    assert!(compute_eigenlib(&[]).is_err());
}

#[test]
fn test_too_large() {
    let mut rng = rand_pcg::Pcg64Mcg::new(0);
    (0..8)
        .map(|_| {
            let len = rng.gen_range(eigenda_kzg::MAX_BLOB_SIZE + 1..eigenda_kzg::MAX_BLOB_SIZE * 4);
            sample(&mut rng, len)
        })
        .collect::<Vec<_>>()
        .par_iter()
        .for_each(|x| {
            assert!(compute_native(x).is_err());
            assert!(compute_sp1(x).is_err());
            assert!(compute_eigenlib(x).is_err());
        });
}

#[test]
fn test_largest() {
    let mut rng = rand_pcg::Pcg64Mcg::new(0);
    (0..8)
        .map(|_| sample(&mut rng, eigenda_kzg::MAX_BLOB_SIZE))
        .collect::<Vec<_>>()
        .par_iter()
        .for_each(|x| {
            let expected = compute_eigenlib(x).unwrap();
            assert_eq!(compute_native(x).unwrap(), expected);
            assert_eq!(compute_sp1(x).unwrap(), expected);
        })
}

#[test]
fn test_zeros() {
    let mut rng = rand_pcg::Pcg64Mcg::new(0);
    (0..8)
        .map(|_| rng.gen_range(1..=eigenda_kzg::MAX_BLOB_SIZE))
        .collect::<Vec<_>>()
        .par_iter()
        .for_each(|&len| {
            let x = vec![0; len];
            assert_eq!(compute_eigenlib(&x).unwrap(), [0; 64]);
            assert_eq!(compute_native(&x).unwrap(), [0; 64]);
            assert_eq!(compute_sp1(&x).unwrap(), [0; 64]);
        });
}

#[test]
fn test_random() {
    let mut rng = rand_pcg::Pcg64Mcg::new(0);
    (0..1024)
        .map(|_| {
            let len = rng.gen_range(1..=eigenda_kzg::MAX_BLOB_SIZE);
            sample(&mut rng, len)
        })
        .collect::<Vec<_>>()
        .par_iter()
        .for_each(|x| {
            let expected = compute_eigenlib(&x).unwrap();
            assert_eq!(compute_native(&x).unwrap(), expected);
            assert_eq!(compute_sp1(&x).unwrap(), expected);
        });
}
