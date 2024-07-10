mod points;

// Bytes in a scalar.
const ELEM_SIZE: usize = 32;

// Each chunk is padded to 32 bytes to match serialization requirements.
const CHUNK_SIZE: usize = ELEM_SIZE - 1;

/// Blobs larger than this size return an error.
pub const MAX_BLOB_SIZE: usize = points::G1_EVALS[points::G1_EVALS.len() - 1].len() * CHUNK_SIZE;

/// Computes the commitment of a blob of data.
///
/// You **do not** need to call [`canonical_encode`], as this function already
/// inserts padding as per EigenDA's [blob serialization requirements].
/// Zero-length blobs and blobs larger than [`MAX_BLOB_SIZE`] return an error.
/// All other blobs return a 64-byte commitment.
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

#[cfg(any(
    test,
    all(
        target_os = "zkvm",
        target_vendor = "succinct",
        target_arch = "riscv32"
    )
))]
fn msm_zkvm(gs: &[[u64; 8]], xs: &[u8]) -> Option<[u8; 64]> {
    #![allow(clippy::assertions_on_constants)]
    use std::mem::{align_of, size_of};

    // Sanity checks to ensure casting is safe.
    const _: () = assert!(std::cfg!(target_endian = "little"));
    const _: () = assert!(size_of::<[u64; 8]>() == size_of::<[u32; 16]>());
    const _: () = assert!(size_of::<[u32; 16]>() == size_of::<[u8; 64]>());
    const _: () = assert!(align_of::<[u64; 8]>() >= align_of::<[u32; 16]>());
    const _: () = assert!(align_of::<[u32; 16]>() >= align_of::<[u8; 64]>());

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

    // SAFETY: Per assertions above.
    let gs: &[[u32; 16]] = unsafe { &*(gs as *const _ as *const _) };
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

    // SAFETY: Per const assertions above.
    Some(unsafe { std::mem::transmute(r?) })
}

fn validate_blob(xs: &[u8]) -> Result<&'static [[u64; 8]], CommitError> {
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

    Ok(points::G1_EVALS[l])
}

#[cfg(all(
    target_os = "zkvm",
    target_vendor = "succinct",
    target_arch = "riscv32"
))]
#[inline]
fn commit_(xs: &[u8]) -> Result<Option<[u8; 64]>, CommitError> {
    Ok(msm_zkvm(validate_blob(xs)?, xs))
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

    let gs = validate_blob(xs)?;

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

    let gs = gs
        .iter()
        // IMPORTANT: Ensure we match the length of the input data.
        .take(es.len())
        .map(|x| {
            let g = G1Affine::new(
                Fq::from_bigint(BigInt::new(x[..4].try_into().unwrap())).unwrap(),
                Fq::from_bigint(BigInt::new(x[4..].try_into().unwrap())).unwrap(),
            );
            assert!(g.is_on_curve());
            g
        })
        .collect::<Vec<_>>();

    let len = gs.len().min(es.len());
    let gs = &gs[..len];
    let es = &es[..len];
    let c = G1Projective::msm(gs, es).unwrap().into_affine();
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
mod polyfill {
    use bnum::types::{U256, U512};
    use bnum::BTryFrom;

    const BASE_MOD: U256 = U256::parse_str_radix(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        10,
    );
    const BASE_MOD_U512: U512 = U512::parse_str_radix(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        10,
    );

    #[derive(Debug, PartialEq, Eq)]
    pub struct G1(U256, U256);

    fn sub(a: U256, b: U256) -> U256 {
        (a + BASE_MOD - b) % BASE_MOD
    }

    fn mul(a: U256, b: U256) -> U256 {
        let a = <U512 as BTryFrom<U256>>::try_from(a).unwrap();
        let b = <U512 as BTryFrom<U256>>::try_from(b).unwrap();
        let a = (a * b) % BASE_MOD_U512;
        <U256 as BTryFrom<U512>>::try_from(a).unwrap()
    }

    fn sq(a: U256) -> U256 {
        let a = <U512 as BTryFrom<U256>>::try_from(a).unwrap();
        let a = (a * a) % BASE_MOD_U512;
        <U256 as BTryFrom<U512>>::try_from(a).unwrap()
    }

    fn div(a: U256, b: U256) -> U256 {
        mul(a, pow(b, BASE_MOD - U256::TWO))
    }

    fn pow(a: U256, e: U256) -> U256 {
        let a = <U512 as BTryFrom<U256>>::try_from(a).unwrap();
        let mut r = U512::ONE;
        for bit in (0..e.bits()).rev() {
            if r != U512::ONE {
                r *= r;
                r %= BASE_MOD_U512;
            }

            if e.bit(bit) {
                r *= a;
                r %= BASE_MOD_U512;
            }
        }
        <U256 as BTryFrom<U512>>::try_from(r).unwrap()
    }

    impl G1 {
        pub fn from_le_bytes(bytes: &[u32]) -> Self {
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            for i in 0..8 {
                x[i * 4..][..4].copy_from_slice(&bytes[i].to_le_bytes());
                y[i * 4..][..4].copy_from_slice(&bytes[i + 8].to_le_bytes());
            }
            let x = U256::from_le_slice(&x).unwrap();
            let y = U256::from_le_slice(&y).unwrap();
            G1(x, y)
        }

        pub fn to_le_bytes(&self) -> [u32; 16] {
            let mut x = self.0.to_radix_le(256);
            x.extend(std::iter::repeat(0).take(32 - x.len()));
            let mut y = self.1.to_radix_le(256);
            y.extend(std::iter::repeat(0).take(32 - y.len()));
            let mut r = [0u32; 16];
            for i in 0..8 {
                r[i] = u32::from_le_bytes(x[i * 4..][..4].try_into().unwrap());
                r[i + 8] = u32::from_le_bytes(y[i * 4..][..4].try_into().unwrap());
            }
            r
        }

        pub fn double(&mut self) {
            let slope = div(sq(self.0) * U256::THREE, self.1 * U256::TWO);
            let x = sub(sq(slope), self.0 * U256::TWO);
            let y = sub(mul(slope, sub(self.0, x)), self.1);
            *self = G1(x, y);
        }

        pub fn add_assign(&mut self, q: &G1) {
            let slope = div(sub(q.1, self.1), sub(q.0, self.0));
            let x = sub(sq(slope), (self.0 + q.0) % BASE_MOD);
            let y = sub(mul(slope, sub(self.0, x)), self.1);
            *self = G1(x, y);
        }
    }

    #[test]
    fn g1_double() {
        let r = G1(
            U256::parse_str_radix(
                "1368015179489954701390400359078579693043519447331113978918064868415326638035",
                10,
            ),
            U256::parse_str_radix(
                "9918110051302171585080402603319702774565515993150576347155970296011118125764",
                10,
            ),
        );
        let mut g = G1::from_le_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
        g.double();
        assert_eq!(g, r);
    }

    #[test]
    fn g1_add() {
        let r = G1(
            U256::parse_str_radix(
                "3353031288059533942658390886683067124040920775575537747144343083137631628272",
                10,
            ),
            U256::parse_str_radix(
                "19321533766552368860946552437480515441416830039777911637913418824951667761761",
                10,
            ),
        );
        let mut a = G1::from_le_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
        let mut b = G1::from_le_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
        b.double();
        a.add_assign(&b);
        assert_eq!(a, r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq, G1Affine, G1Projective};
    use ark_ec::{AffineRepr as _, CurveGroup as _, Group as _};
    use ark_ff::{BigInteger as _, PrimeField as _};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use std::sync::OnceLock;

    fn into_g1(g: &[u32]) -> ark_bn254::G1Affine {
        assert!(g.len() == 16);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        for i in 0..8 {
            x[i * 4..][..4].copy_from_slice(&g[i].to_le_bytes());
            y[i * 4..][..4].copy_from_slice(&g[i + 8].to_le_bytes());
        }
        G1Affine::new(
            Fq::from_le_bytes_mod_order(&x),
            Fq::from_le_bytes_mod_order(&y),
        )
    }

    fn from_g1(g: ark_bn254::G1Affine) -> [u32; 16] {
        let (x, y) = g.xy().unwrap();
        let x = x.into_bigint().to_bytes_le();
        let y = y.into_bigint().to_bytes_le();
        assert!(x.len() <= 32);
        assert!(y.len() <= 32);
        let mut r = [0u32; 16];
        for i in 0..8 {
            r[i] = u32::from_le_bytes(x[i * 4..][..4].try_into().unwrap());
            r[i + 8] = u32::from_le_bytes(y[i * 4..][..4].try_into().unwrap());
        }
        r
    }

    // Polyfill the zkvm syscalls so we can test the prover version
    // without running the prover, which is quite expensive.

    #[no_mangle]
    extern "C" fn syscall_bn254_add(p: *mut u32, q: *const u32) {
        let p = unsafe { std::slice::from_raw_parts_mut(p, 16) };
        let q = unsafe { std::slice::from_raw_parts(q, 16) };
        //let r = (into_g1(p) + into_g1(q)).into_affine();
        //p.copy_from_slice(&from_g1(r));
        let mut r = polyfill::G1::from_le_bytes(p);
        let q = polyfill::G1::from_le_bytes(q);
        r.add_assign(&q);
        p.copy_from_slice(&r.to_le_bytes());
    }

    #[no_mangle]
    extern "C" fn syscall_bn254_double(p: *mut u32) {
        let p = unsafe { std::slice::from_raw_parts_mut(p, 16) };
        //let r = G1Projective::from(into_g1(p)).double().into_affine();
        //p.copy_from_slice(&from_g1(r));
        let mut r = polyfill::G1::from_le_bytes(p);
        r.double();
        p.copy_from_slice(&r.to_le_bytes());
    }

    fn commit_zkvm(xs: &[u8]) -> Result<[u8; 64], CommitError> {
        Ok(msm_zkvm(validate_blob(xs)?, xs).unwrap_or([0; 64]))
    }

    fn commit_eigen(xs: &[u8]) -> Result<[u8; 64], Box<dyn std::error::Error>> {
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
        assert_eq!(commit_zkvm(&[]), Err(CommitError::Empty));
        assert!(commit_eigen(&[]).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn commit_too_large(xs in vec(any::<u8>(), MAX_BLOB_SIZE + 1..MAX_BLOB_SIZE * 2)) {
            prop_assert_eq!(commit(&xs), Err(CommitError::TooLarge));
            prop_assert_eq!(commit_zkvm(&xs), Err(CommitError::TooLarge));
            prop_assert!(commit_eigen(&xs).is_err());
        }

        #[test]
        fn commit_largest(xs in vec(any::<u8>(), MAX_BLOB_SIZE)) {
            let expected = commit_eigen(&xs).unwrap();
            prop_assert_eq!(commit(&xs).unwrap(), expected);
            prop_assert_eq!(commit_zkvm(&xs).unwrap(), expected);
        }

        #[test]
        fn commit_zeroes(xs in vec(0u8..=0, 1..=MAX_BLOB_SIZE)) {
            prop_assert_eq!(commit(&xs).unwrap(), [0; 64]);
            prop_assert_eq!(commit_zkvm(&xs).unwrap(), [0; 64]);
            prop_assert_eq!(commit_eigen(&xs).unwrap(), [0; 64]);
        }

        #[test]
        //fn commit_random(xs in vec(any::<u8>(), 1..=MAX_BLOB_SIZE)) {
        fn commit_random(xs in vec(any::<u8>(), 1_0_000..=1_0_000)) {
            //let expected = commit_eigen(&xs).unwrap();
            //prop_assert_eq!(commit(&xs).unwrap(), expected);
            let t = std::time::Instant::now();
            commit_zkvm(&xs).unwrap();
            //prop_assert_eq!(commit_zkvm(&xs).unwrap(), expected);
            println!("elapsed zkvm: {:?}", t.elapsed());
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
