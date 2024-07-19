mod points;

// Bytes in a scalar.
const ELEM_SIZE: usize = 32;

// Each chunk is padded to 32 bytes to match serialization requirements.
const CHUNK_SIZE: usize = ELEM_SIZE - 1;

/// Blobs larger than this size return an error.
pub const MAX_BLOB_SIZE: usize =
    points::G1_EVALS_U8_LE[points::G1_EVALS_U8_LE.len() - 1].len() * CHUNK_SIZE;

/// Computes the commitment of a blob of data.
///
/// You **do not** need to call [`canonical_encode`], as this function already
/// inserts padding as per EigenDA's [blob serialization requirements]. If you
/// need to compute the commitment to a blob of data that is already serialized,
/// use [`canonical_decode`] to deserialize it first.
///
/// Zero-length blobs and blobs larger than [`MAX_BLOB_SIZE`] return an error.
/// All other blobs return a valid 64-byte commitment.
///
/// The commitment is a G1 point on the BN254 curve, serialized as a
/// 64-byte array of little-endian bytes. The first 32 bytes correspond
/// to the x-coordinate, and the latter 32-bytes correspond to the
/// y-coordinate. The identity is serialized as 64 zero bytes.
///
/// [blob serialization requirements]: https://docs.eigenlayer.xyz/eigenda/integrations-guides/dispersal/api-documentation/blob-serialization-requirements
pub fn commit(xs: &[u8]) -> Result<[u8; 64], CommitError> {
    commit_(xs).map(|x| x.unwrap_or([0; 64]))
}

/// Possible errors returned by [`commit`].
///
/// This only happens if the blob length is out of range. If
/// the blob has length within `1..=MAX_BLOB_SIZE`, [`commit`]
/// will always return ok.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CommitError {
    Empty,
    TooLarge,
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitError::Empty => write!(f, "blob is empty"),
            CommitError::TooLarge => write!(f, "blob is too large"),
        }
    }
}

impl std::error::Error for CommitError {}

/// Serializes a blob of data per the [blob serialization requirements].
///
/// This function **does not** need to be called before [`commit`]
/// as [`commit`] already internally serializes the blob.
///
/// [blob serialization requirements]: https://docs.eigenlayer.xyz/eigenda/integrations-guides/dispersal/api-documentation/blob-serialization-requirements
pub fn canonical_encode(xs: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(canonical_encode_len(xs));
    let mut c = xs.chunks_exact(CHUNK_SIZE);

    for x in &mut c {
        r.push(0);
        r.extend_from_slice(x);
    }

    if !c.remainder().is_empty() {
        r.push(0);
        r.extend_from_slice(c.remainder());
    }

    r
}

/// Returns the length of the blob that would be serialized by [`canonical_encode`].
///
/// This function is useful if you only need to know the length of the serialized
/// data, without actually serializing it. For example, if you need to validate
/// the length returned by the disperser.
pub fn canonical_encode_len(xs: &[u8]) -> usize {
    xs.len() + xs.len().div_ceil(CHUNK_SIZE)
}

/// Deserializes a blob of data serialized per the [blob serialization requirements].
///
/// This function returns an error if the input is not serialized correctly. Is the
/// inverse of [`canonical_encode`]. Note that the conversion is lossless, i.e. the
/// original data is returned.
///
/// [blob serialization requirements]: https://docs.eigenlayer.xyz/eigenda/integrations-guides/dispersal/api-documentation/blob-serialization-requirements
pub fn canonical_decode(xs: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut r = Vec::with_capacity(xs.len() - xs.len().div_ceil(ELEM_SIZE));
    let mut c = xs.chunks_exact(ELEM_SIZE);
    let mut i = 0;

    for x in &mut c {
        if x[0] != 0 {
            return Err(DecodeError::MissingPadding(i));
        }

        i += ELEM_SIZE;
        r.extend_from_slice(&x[1..]);
    }

    if !c.remainder().is_empty() {
        if c.remainder().len() == 1 {
            return Err(DecodeError::ExtraByte);
        }

        if c.remainder()[0] != 0 {
            return Err(DecodeError::MissingPadding(i));
        }

        r.extend_from_slice(&c.remainder()[1..]);
    }

    Ok(r)
}

/// Possible errors returned by [`canonical_decode`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DecodeError {
    /// The byte at `.0` is not zero.
    MissingPadding(usize),
    /// The last 32 byte chunk has a single byte.
    ExtraByte,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::MissingPadding(i) => write!(f, "invalid non-zero byte at {}", i),
            DecodeError::ExtraByte => write!(f, "extra byte in last chunk"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(all(
    target_os = "zkvm",
    target_vendor = "succinct",
    target_arch = "riscv32"
))]
fn msm_zkvm(gs: &[[u32; 16]], xs: &[u8]) -> Option<[u8; 64]> {
    #![allow(clippy::assertions_on_constants)]
    use std::mem::{align_of, size_of};

    extern "C" {
        fn syscall_bn254_add(p: *mut u32, q: *const u32);
        fn syscall_bn254_double(p: *mut u32);
    }

    fn bn254_add(p: &mut [u32; 16], q: &[u32; 16]) {
        unsafe { syscall_bn254_add(p.as_mut_ptr(), q.as_ptr()) }
    }

    fn bn254_double(p: &mut [u32; 16]) {
        unsafe { syscall_bn254_double(p.as_mut_ptr()) }
    }

    // `e` is big-endian.
    fn bn254_mul(g: &[u32; 16], e: &[u8; CHUNK_SIZE]) -> Option<[u32; 16]> {
        let mut r: Option<[u32; 16]> = None;
        for byte in e.iter() {
            for bit in (0..8).rev() {
                if let Some(r) = &mut r {
                    bn254_double(r);
                }

                if byte >> bit & 1 == 0 {
                    continue;
                }

                match &mut r {
                    Some(r) => bn254_add(r, g),
                    None => r = Some(*g),
                }
            }
        }
        r
    }

    let es = xs.chunks(CHUNK_SIZE).map(|x| {
        let mut buf = [0; CHUNK_SIZE];
        buf[..x.len()].copy_from_slice(x);
        buf
    });
    let mut r: Option<[u32; 16]> = None;

    for (g, e) in gs.iter().zip(es) {
        if let Some(g) = bn254_mul(g, &e) {
            match &mut r {
                Some(r) => bn254_add(r, &g),
                None => r = Some(g),
            }
        }
    }

    // Sanity checks to ensure casting is safe.
    const _: () = assert!(std::cfg!(target_endian = "little"));
    const _: () = assert!(size_of::<[u32; 16]>() == size_of::<[u8; 64]>());
    const _: () = assert!(align_of::<[u32; 16]>() >= align_of::<[u8; 64]>());

    // SAFETY: Per const assertions above.
    Some(unsafe { std::mem::transmute(r?) })
}

/// Validates blob size, returning the appropriate index of `points::G1_EVALS`.
fn validate_blob(xs: &[u8]) -> Result<usize, CommitError> {
    if xs.is_empty() {
        return Err(CommitError::Empty);
    }

    if xs.len() > MAX_BLOB_SIZE {
        return Err(CommitError::TooLarge);
    }

    let l = xs
        .len()
        .div_ceil(CHUNK_SIZE)
        .next_power_of_two()
        .trailing_zeros() as usize;

    Ok(l)
}

#[cfg(all(
    target_os = "zkvm",
    target_vendor = "succinct",
    target_arch = "riscv32"
))]
#[inline]
fn commit_(xs: &[u8]) -> Result<Option<[u8; 64]>, CommitError> {
    Ok(msm_zkvm(points::G1_EVALS_U32_LE[validate_blob(xs)?], xs))
}

#[cfg(not(all(
    target_os = "zkvm",
    target_vendor = "succinct",
    target_arch = "riscv32"
)))]
#[inline]
fn commit_(xs: &[u8]) -> Result<Option<[u8; 64]>, CommitError> {
    use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
    use ark_ec::AffineRepr;
    use ark_ec::{CurveGroup as _, VariableBaseMSM as _};
    use ark_ff::{BigInt, BigInteger, PrimeField};
    use std::sync::OnceLock;

    fn u64_from_u8(x: [u8; 32]) -> [u64; 4] {
        let mut r = [0; 4];
        for i in 0..4 {
            r[i] = u64::from_le_bytes(x[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        r
    }

    // Used only as an initializer.
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: OnceLock<&'static [G1Affine]> = OnceLock::new();
    const LEN: usize = points::G1_EVALS_U8_LE.len();
    static MEMO: [OnceLock<&'static [G1Affine]>; LEN] = [INIT; LEN];

    let i = validate_blob(xs)?;
    let gs = MEMO[i].get_or_init(|| {
        let gs = points::G1_EVALS_U8_LE[i]
            .iter()
            .map(|xy: &[u8; 64]| {
                let (x, y) = xy.split_at(32);
                let x = u64_from_u8(x.try_into().unwrap());
                let y = u64_from_u8(y.try_into().unwrap());
                let g = G1Affine::new(
                    Fq::from_bigint(BigInt::new(x)).unwrap(),
                    Fq::from_bigint(BigInt::new(y)).unwrap(),
                );
                assert!(g.is_on_curve());
                g
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Box::leak(gs)
    });

    let es = xs
        .chunks(CHUNK_SIZE)
        .map(|x| {
            let mut buf = [0; CHUNK_SIZE];
            buf[..x.len()].copy_from_slice(x);
            buf.reverse();
            // `be` variant seems to internally allocate.
            Fr::from_le_bytes_mod_order(&buf)
        })
        .collect::<Vec<_>>();

    assert!(es.len() <= gs.len());
    let gs = &gs[..es.len()];
    let c = G1Projective::msm(gs, &es).unwrap().into_affine();
    let Some((x, y)) = c.xy() else {
        return Ok(None);
    };
    let x = x.into_bigint().to_bytes_le();
    let y = y.into_bigint().to_bytes_le();

    assert!(x.len() <= 32);
    assert!(y.len() <= 32);

    let mut r = [0u8; 64];
    r[..x.len()].copy_from_slice(&x);
    r[32..y.len() + 32].copy_from_slice(&y);
    Ok(Some(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    /// Computes a commitment using `rust-kzg-bn254`.
    ///
    /// Used to compare our implementation against the official one provided
    /// by EigenDA.
    fn commit_eigen(xs: &[u8]) -> Result<[u8; 64], Box<dyn std::error::Error>> {
        use ark_ec::AffineRepr as _;
        use ark_ff::{BigInteger as _, PrimeField as _};
        use std::sync::OnceLock;

        static MEMO: OnceLock<rust_kzg_bn254::kzg::Kzg> = OnceLock::new();
        let kzg = MEMO.get_or_init(|| {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("points");
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
            let mut blob = rust_kzg_bn254::blob::Blob::new(xs.to_vec());
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

    #[test]
    fn commit_empty() {
        assert_eq!(commit(&[]), Err(CommitError::Empty));
        assert!(commit_eigen(&[]).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn commit_too_large(xs in vec(any::<u8>(), MAX_BLOB_SIZE + 1..MAX_BLOB_SIZE * 2)) {
            prop_assert_eq!(commit(&xs), Err(CommitError::TooLarge));
            prop_assert!(commit_eigen(&xs).is_err());
        }

        #[test]
        fn commit_zeroes(xs in vec(0u8..=0, 1..=MAX_BLOB_SIZE)) {
            prop_assert_eq!(commit(&xs).unwrap(), [0; 64]);
            prop_assert_eq!(commit_eigen(&xs).unwrap(), [0; 64]);
        }

        #[test]
        fn commit_largest(xs in vec(any::<u8>(), MAX_BLOB_SIZE)) {
            let expected = commit_eigen(&xs).unwrap();
            prop_assert_eq!(commit(&xs).unwrap(), expected);
        }

        #[test]
        fn commit_random(xs in vec(any::<u8>(), 1..=MAX_BLOB_SIZE)) {
            let expected = commit_eigen(&xs).unwrap();
            prop_assert_eq!(commit(&xs).unwrap(), expected);
        }

        #[test]
        fn commit_trailing_zeroes(
            xs in (1..=MAX_BLOB_SIZE)
                .prop_flat_map(|len| (Just(len), vec(any::<u8>(), 0..len)))
                .prop_map(|(len, mut xs)| {
                    xs.extend_from_slice(&vec![0; len - xs.len()]);
                    xs
                })
        ) {
            let expected = commit_eigen(&xs).unwrap();
            prop_assert_eq!(commit(&xs).unwrap(), expected);
        }
    }

    #[test]
    fn canonical_enc_dec_empty() {
        let enc = canonical_encode(&[]);
        let dec = canonical_decode(&enc).unwrap();
        assert!(enc.is_empty());
        assert!(dec.is_empty());
    }

    proptest! {
        #[test]
        fn matches_kzgpad(xs in vec(any::<u8>(), 0..8192)) {
            let enc = canonical_encode(&xs);
            let dec = canonical_decode(&enc).unwrap();

            prop_assert_eq!(&enc, &kzgpad_rs::convert_by_padding_empty_byte(&xs));
            prop_assert_eq!(&dec, &kzgpad_rs::remove_empty_byte_from_padded_bytes(&enc));
        }

        #[test]
        fn canonical_enc_dec(xs in vec(any::<u8>(), 0..8192)) {
            let enc = canonical_encode(&xs);
            let dec = canonical_decode(&enc).unwrap();
            prop_assert_eq!(xs, dec);
        }

        #[test]
        fn canonical_len(xs in vec(any::<u8>(), 0..8192)) {
            let enc = canonical_encode(&xs);
            prop_assert_eq!(enc.len(), canonical_encode_len(&xs));
        }

        #[test]
        fn canonical_dec_err_padding(
            b in 1u8..,
            (i, xs) in (1usize..=100)
                .prop_flat_map(|len| (0..len, vec(any::<u8>(), len)))
        ) {
            let i = i / ELEM_SIZE * ELEM_SIZE;
            let mut enc = canonical_encode(&xs);
            enc[i] = b;
            prop_assert_eq!(canonical_decode(&enc), Err(DecodeError::MissingPadding(i)));
        }

        #[test]
        fn canonical_dec_err_extra_byte(
            b in 0u8..,
            xs in (0usize..=20).prop_flat_map(|i| vec(any::<u8>(), i * CHUNK_SIZE))
        ) {
            let mut enc = canonical_encode(&xs);
            enc.push(b);
            prop_assert_eq!(canonical_decode(&enc), Err(DecodeError::ExtraByte));
        }
    }
}
