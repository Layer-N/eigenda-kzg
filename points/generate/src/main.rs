//! Stores the x and y coordinates of the G1 points in standard and montgomery form.

use ark_ec::AffineRepr as _;
use ark_ff::{BigInteger as _, PrimeField as _};
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
        262144,
    )
    .unwrap();

    // Write the x and y coordinates of the point in both
    // standard and montgomery form.

    let gs = kzg.get_g1_points();
    let mut std = std::fs::File::create_new(root.join("g1_coeff_std.bin"))?;
    let mut mont = std::fs::File::create_new(root.join("g1_coeff_mont.bin"))?;

    for g in gs {
        assert!(!g.is_zero());
        let (x, y) = g.xy().unwrap();

        {
            let x = x.into_bigint().to_bytes_le();
            let y = y.into_bigint().to_bytes_le();
            assert_eq!(x.len(), 32);
            assert_eq!(y.len(), 32);
            std.write_all(&x)?;
            std.write_all(&y)?;
        }

        {
            let x: [u64; 4] = x.0 .0;
            let y: [u64; 4] = y.0 .0;
            for &x in &x {
                mont.write_all(&x.to_le_bytes())?;
            }
            for &y in &y {
                mont.write_all(&y.to_le_bytes())?;
            }
        }
    }

    Ok(())
}
