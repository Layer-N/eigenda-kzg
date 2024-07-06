//! Precomputes the IFFT of the SRS G1 points for the KZG10 scheme.

use ark_ec::AffineRepr as _;
use ark_ff::{BigInteger as _, PrimeField as _};
use rayon::iter::{IntoParallelIterator, ParallelIterator as _};
use std::io::Write as _;
use std::path::Path;

const MANIFEST: &str = std::env!("CARGO_MANIFEST_DIR");

fn main() -> std::io::Result<()> {
    let root = Path::new(MANIFEST).join("..");
    let g1 = root.join("g1.point");
    let g2 = root.join("g2.point.powerOf2");

    if !g1.try_exists()? || !g2.try_exists()? {
        panic!("g1.point and g2.point.powerOf2 must exist in the root directory");
    }

    let kzg = rust_kzg_bn254::kzg::Kzg::setup(
        g1.to_str().unwrap(),
        "",
        g2.to_str().unwrap(),
        268435456,
        131072,
    )
    .unwrap();

    // 131072 = 2^17
    let iffts = (0..=17)
        .into_par_iter()
        .map(|i| (i, kzg.g1_ifft(1 << i).unwrap()))
        .collect::<Vec<_>>();

    for (i, gs) in iffts {
        let mut f = std::fs::File::create_new(root.join(format!("g1_ifft_{:02}.bin", i)))?;

        for g in gs {
            assert!(!g.is_zero());
            let (x, y) = g.xy().unwrap();
            let x = x.into_bigint().to_bytes_le();
            let y = y.into_bigint().to_bytes_le();
            assert_eq!(x.len(), 32);
            assert_eq!(y.len(), 32);
            f.write_all(&x)?;
            f.write_all(&y)?;
        }
    }

    Ok(())
}
