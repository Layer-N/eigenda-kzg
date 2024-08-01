//! Prover-friendly KZG commitments on BN254.
//!
//! ```rust
//! # let data = &[1, 2, 3, 4];
//! #
//! # fn disperse(data: &[u8]) -> [u8; 64] {
//! #     eigenda_kzg::commit(&eigenda_kzg::decode_delimited(data).unwrap()).unwrap()
//! # }
//! let actual = disperse(&eigenda_kzg::encode_delimited(data));
//! let expected = eigenda_kzg::commit(data).unwrap();
//!
//! assert_eq!(actual, expected);
//! ```

mod points;

// Bytes in a scalar.
const ELEM_SIZE: usize = 32;

// Each chunk is padded to 32 bytes to match serialization requirements.
const CHUNK_SIZE: usize = ELEM_SIZE - 1;

/// Blobs larger than this size return an error.
// -1 to account for sentinel.
pub const MAX_BLOB_SIZE: usize = points::G1_COEFF_MONT_U8_LE.len() * CHUNK_SIZE - 1;

/// The sentinel appended to the end of the array prior to committing.
///
/// This and adding the appropriate padding is already handled by [`commit`].
pub const SENTINEL: u8 = 1;
const _: () = assert!(SENTINEL != 0);

/// Computes the commitment of the given data.
///
/// You **do not** need to call [`encode_delimited`], as this function already
/// appends the sentinel and inserts padding. If you need to compute the commitment
/// to a blob of data that is already serialized, use [`decode_delimited`] to
/// deserialize it first.
///
/// Blobs larger than [`MAX_BLOB_SIZE`] return an error. All other blobs return a
/// valid, non-zero 64-byte commitment.
///
/// The commitment is a G1 point on the BN254 curve, serialized as a
/// 64-byte array of little-endian bytes. The first 32 bytes correspond
/// to the x-coordinate, and the latter 32-bytes correspond to the
/// y-coordinate. The identity is never serialized.
pub fn commit(data: &[u8]) -> Result<[u8; 64], CommitError> {
    if data.len() > MAX_BLOB_SIZE {
        return Err(CommitError {});
    }

    Ok(commit_(data))
}

/// Error returned by [`commit`].
///
/// This only happens if the blob is too large. If the blob has length less
/// than or equal to [`MAX_BLOB_SIZE`], [`commit`] will always return ok.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CommitError {}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blob is too large")
    }
}

impl std::error::Error for CommitError {}

/// Splits the slice into a slice of N-element arrays, starting at the beginning of the slice, and
/// a remainder slice with length strictly less than N.
///
/// Taken from unstable feature [`array_chunks`]. Can be removed when the feature lands.
///
/// [`array_chunks`]: <https://github.com/rust-lang/rust/issues/74985>
const fn as_chunks<const N: usize>(xs: &[u8]) -> (&[[u8; N]], &[u8]) {
    assert!(N != 0);
    let (head, remainder) = xs.split_at(xs.len() / N * N);
    assert!(head.len() % N == 0);
    let new_len = head.len() / N;
    let array_slice = unsafe { std::slice::from_raw_parts(head.as_ptr().cast(), new_len) };
    (array_slice, remainder)
}

/// Returns the length of the blob that would be serialized by [`encode_delimited`].
///
/// This function is useful if you only need to know the length of the serialized
/// data without actually serializing it. For example, if you need to validate
/// the length returned by the disperser.
///
/// This is guaranteed to be a multiple of 32.
pub fn encode_delimited_len(data_len: usize) -> usize {
    data_len
        .checked_add(1)
        .unwrap()
        .div_ceil(CHUNK_SIZE)
        .checked_mul(ELEM_SIZE)
        .unwrap()
}

/// Serializes a blob of data to sentinel-delimited encoding.
///
/// This is similar to EigenDA's [`kzgpad`] format, but with a sentinel
/// appended to the end of the blob prior to encoding. The sentinel is
/// necessary for the original data to be recoverable when the data
/// is zero-padded to a 32-byte boundary.
///
/// This function **does not** need to be called before [`commit`]
/// as [`commit`] already internally serializes the blob with this
/// format.
///
/// This function is meant to be used when you need to serialize the
/// data prior to sending it to the disperser. Otherwise, the data
/// itself should be used directly with [`commit`].
///
/// [`kzgpad`]: https://docs.eigenlayer.xyz/eigenda/integrations-guides/dispersal/api-documentation/blob-serialization-requirements
pub fn encode_delimited(data: &[u8]) -> Vec<u8> {
    let l = encode_delimited_len(data.len());
    let (xs, x) = as_chunks::<CHUNK_SIZE>(data);
    let mut r = Vec::with_capacity(l);

    for x in xs {
        r.push(0);
        r.extend_from_slice(x);
    }

    assert!(x.len() < CHUNK_SIZE);
    r.push(0);
    r.extend_from_slice(x);
    r.push(SENTINEL);
    r.resize(r.len().div_ceil(ELEM_SIZE) * ELEM_SIZE, 0);

    assert!(r.len() == l);
    assert!(r.len() % ELEM_SIZE == 0);

    r
}

/// Deserializes a blob of data serialized from sentinel-delimited encoding.
///
/// This function returns an error if the input is not serialized correctly. Is the
/// inverse of [`encode_delimited`]. Note that the conversion is lossless, i.e. the
/// original data is returned.
///
/// The requirements for the input are:
///
/// - The length must be non-zero.
/// - The length must be a multiple of 32.
/// - The last non-zero byte must be [`SENTINEL`] and in the last 32-byte chunk.
/// - Every 32-byte chunk must have the first byte as zero.
pub fn decode_delimited(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    // This funky destructuring validates the length.
    let ([xs @ .., x], []) = as_chunks::<ELEM_SIZE>(data) else {
        return Err(DecodeError::InvalidLength);
    };

    let sentinel = x
        .iter()
        .rposition(|c| *c != 0)
        .ok_or(DecodeError::MissingSentinel)?;

    if x[sentinel] != SENTINEL {
        return Err(DecodeError::InvalidSentinel);
    }

    assert!(sentinel > 0);

    // -1 deals with the 0 byte in the last chunk.
    let l = CHUNK_SIZE * xs.len() + sentinel - 1;
    let mut r = Vec::with_capacity(l);

    for (i, c) in xs.iter().enumerate() {
        if c[0] != 0 {
            return Err(DecodeError::MissingPadding(i * ELEM_SIZE));
        }

        r.extend_from_slice(&c[1..]);
    }

    if x[0] != 0 {
        return Err(DecodeError::MissingPadding(xs.len() * ELEM_SIZE));
    }

    r.extend_from_slice(&x[1..sentinel]);
    assert!(r.len() == l);
    Ok(r)
}

/// Error returned by [`decode_delimited`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DecodeError {
    /// The byte at `.0` is not zero.
    MissingPadding(usize),
    /// The last 32 byte chunk is missing the sentinel.
    MissingSentinel,
    /// Length is not a multiple of 32.
    InvalidLength,
    /// Sentinel is not [`SENTINEL`].
    InvalidSentinel,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::MissingPadding(i) => write!(f, "invalid non-zero byte at {}", i),
            DecodeError::MissingSentinel => write!(f, "missing sentinel"),
            DecodeError::InvalidLength => write!(f, "length not a multiple of 32"),
            DecodeError::InvalidSentinel => write!(f, "sentinel is not {}", SENTINEL),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Computes the commitment, panicking if the blob is too large.
#[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
#[inline]
fn commit_(xs: &[u8]) -> [u8; 64] {
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

    assert!(xs.len() <= MAX_BLOB_SIZE);
    let gs = points::G1_COEFF_STD_U32_LE;
    let (xs, x) = as_chunks::<CHUNK_SIZE>(xs);

    // Do the last element first, as we know it is non-zero
    // thanks to the sentinel being non-zero. This avoids the
    // need to track if `r` is zero.
    let mut r: [u32; 16] = {
        let mut e = [0; CHUNK_SIZE];
        e[..x.len()].copy_from_slice(x);
        e[x.len()] = SENTINEL;
        bn254_mul(&gs[xs.len()], &e).unwrap()
    };

    for (g, e) in gs.iter().zip(xs) {
        if let Some(g) = bn254_mul(g, e) {
            bn254_add(&mut r, &g);
        }
    }

    // Sanity checks to ensure casting is safe.
    const _: () = assert!(std::cfg!(target_endian = "little"));
    const _: () = assert!(size_of::<[u32; 16]>() == size_of::<[u8; 64]>());
    const _: () = assert!(align_of::<[u32; 16]>() >= align_of::<[u8; 64]>());

    // SAFETY: Per const assertions above.
    unsafe { std::mem::transmute(r) }
}

/// Computes the commitment, panicking if the blob is too large.
#[cfg(not(all(target_os = "zkvm", target_vendor = "succinct")))]
#[inline]
fn commit_(xs: &[u8]) -> [u8; 64] {
    use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
    use ark_ec::AffineRepr;
    use ark_ec::{CurveGroup as _, VariableBaseMSM as _};
    use ark_ff::{BigInt, BigInteger, PrimeField};

    #[allow(long_running_const_eval)]
    const fn u8_to_u64(x: [u8; 32]) -> [u64; 4] {
        let x = unsafe { std::mem::transmute::<_, [[u8; 8]; 4]>(x) };
        let mut r = [0; 4];
        let mut i = 0;
        while i < 4 {
            r[i] = u64::from_le_bytes(x[i]);
            i += 1;
        }
        r
    }

    const LEN: usize = points::G1_COEFF_MONT_U8_LE.len();

    // `static` to keep stack usage small.
    #[allow(long_running_const_eval)]
    static G1_COEFF: &[G1Affine; LEN] = &{
        let mut r = [G1Affine::identity(); LEN];
        let mut i = 0;
        while i < LEN {
            let [x, y] = points::G1_COEFF_MONT_U8_LE[i];
            let x = u8_to_u64(x);
            let y = u8_to_u64(y);
            let g = G1Affine::new_unchecked(
                Fq::new_unchecked(BigInt::new(x)),
                Fq::new_unchecked(BigInt::new(y)),
            );
            r[i] = g;
            i += 1;
        }
        r
    };

    assert!(xs.len() <= MAX_BLOB_SIZE);
    let mut es = Vec::with_capacity(xs.len().div_ceil(CHUNK_SIZE));
    let (xs, x) = as_chunks::<CHUNK_SIZE>(xs);

    es.extend(xs.iter().copied().map(|mut buf| {
        buf.reverse();
        // `be` variant seems to internally allocate.
        Fr::from_le_bytes_mod_order(&buf)
    }));

    assert!(x.len() < MAX_BLOB_SIZE);
    let mut buf = [0; CHUNK_SIZE];
    buf[..x.len()].copy_from_slice(x);
    buf[x.len()] = SENTINEL;
    buf.reverse();
    es.push(Fr::from_le_bytes_mod_order(&buf));

    assert!(es.len() <= G1_COEFF.len());
    let gs = &G1_COEFF[..es.len()];
    let c = G1Projective::msm(gs, &es).unwrap().into_affine();
    let (x, y) = c.xy().expect("should not be zero");
    let x = x.into_bigint().to_bytes_le();
    let y = y.into_bigint().to_bytes_le();

    assert!(x.len() <= 32);
    assert!(y.len() <= 32);

    let mut r = [0u8; 64];
    r[..x.len()].copy_from_slice(&x);
    r[32..y.len() + 32].copy_from_slice(&y);
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    const SAMPLES_DIR: &str = "samples";

    #[test]
    fn delimited_dec_empty() {
        assert_eq!(decode_delimited(&[]), Err(DecodeError::InvalidLength));
    }

    #[test]
    fn delimited_enc_dec_empty() {
        let enc = encode_delimited(&[]);
        let dec = decode_delimited(&enc).unwrap();
        assert!(dec.is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn delimited_len_valid(len in 1..(usize::MAX / 4)) {
            let len = encode_delimited_len(len);
            prop_assert!(len >= ELEM_SIZE);
            prop_assert!(len % ELEM_SIZE == 0);
        }

        #[test]
        fn delimited_enc_dec(xs in vec(any::<u8>(), 0..8192)) {
            let enc = encode_delimited(&xs);
            let dec = decode_delimited(&enc).unwrap();
            prop_assert_eq!(xs, dec);
        }

        #[test]
        fn delimited_len(xs in vec(any::<u8>(), 0..8192)) {
            let enc = encode_delimited(&xs);
            prop_assert_eq!(enc.len(), encode_delimited_len(xs.len()));
            prop_assert_eq!(enc.len() % ELEM_SIZE, 0);
        }

        #[test]
        fn delimited_dec_err_length(
            xs in vec(any::<u8>(), 1..8192)
                .prop_filter(
                    "Values must not have a length multiple of 32",
                    |x| x.len() % ELEM_SIZE != 0,
                )
        ) {
            prop_assert_eq!(decode_delimited(&xs), Err(DecodeError::InvalidLength));
        }

        #[test]
        fn delimited_dec_err_padding(
            b in 1u8..,
            (i, xs) in (1usize..=8192)
                .prop_flat_map(|len| (0..len, vec(any::<u8>(), len)))
        ) {
            let i = i / ELEM_SIZE * ELEM_SIZE;
            let mut enc = encode_delimited(&xs);
            enc[i] = b;
            prop_assert_eq!(decode_delimited(&enc), Err(DecodeError::MissingPadding(i)));
        }

        #[test]
        fn delimited_dec_invalid_sentinel(
            b in (1u8..).prop_filter("Must not be a sentinel", |x| *x != SENTINEL),
            xs in vec(any::<u8>(), 1usize..=8192)
        ) {
            let mut enc = encode_delimited(&xs);
            let i = enc.iter().rposition(|x| *x == SENTINEL).unwrap();
            enc[i] = b;
            prop_assert_eq!(decode_delimited(&enc), Err(DecodeError::InvalidSentinel));
        }

        #[test]
        fn delimited_dec_missing_sentinel(xs in vec(any::<u8>(), 1usize..=8192)) {
            let mut enc = encode_delimited(&xs);
            let len = enc.len();
            enc[len - ELEM_SIZE..].copy_from_slice(&[0; ELEM_SIZE]);
            prop_assert_eq!(decode_delimited(&enc), Err(DecodeError::MissingSentinel));
        }
    }

    // These are sampled from EigenDA's API. Used to ensure that
    // our implementation does not diverge from the reference.
    #[test]
    fn samples() {
        for entry in std::fs::read_dir(SAMPLES_DIR).unwrap() {
            let path = entry.unwrap().path();

            if path.extension().unwrap() == "commit" {
                continue;
            }

            assert_eq!(path.extension().unwrap(), "data");
            let data = std::fs::read(&path).unwrap();
            let expect = std::fs::read(path.with_extension("commit")).unwrap();
            let expect = <[u8; 64]>::try_from(expect).unwrap();
            assert_eq!(commit(&data).unwrap(), expect);
        }
    }

    /// Computes a commitment using `rust-kzg-bn254`, while including
    /// our custom delimited encoding format.
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
            // Our encoding is similar to theirs, but with a sentinel.
            let mut xs = xs.to_vec();
            xs.push(SENTINEL);
            let mut blob = rust_kzg_bn254::blob::Blob::new(xs.to_vec());
            blob.pad_data().unwrap();
            blob.to_polynomial(rust_kzg_bn254::polynomial::PolynomialFormat::InEvaluationForm)?
        };
        let c = kzg.commit(&poly)?;
        let (x, y) = c.xy().expect("should not be zero");
        let x = x.into_bigint().to_bytes_le();
        let y = y.into_bigint().to_bytes_le();
        Ok([x, y].concat().try_into().unwrap())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn commit_too_large(xs in vec(any::<u8>(), MAX_BLOB_SIZE + 1..MAX_BLOB_SIZE * 2)) {
            prop_assert!(commit(&xs).is_err());
        }

        #[test]
        fn commit_zeroes(xs in vec(0u8..=0, 1..=MAX_BLOB_SIZE)) {
            prop_assert_eq!(commit(&xs).unwrap(), commit_eigen(&xs).unwrap());
        }

        #[test]
        fn commit_largest(xs in vec(any::<u8>(), MAX_BLOB_SIZE)) {
            prop_assert_eq!(commit(&xs).unwrap(), commit_eigen(&xs).unwrap());
        }

        #[test]
        fn commit_random(xs in vec(any::<u8>(), 1..=MAX_BLOB_SIZE)) {
            prop_assert_eq!(commit(&xs).unwrap(), commit_eigen(&xs).unwrap());
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
}
