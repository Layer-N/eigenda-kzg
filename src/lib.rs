mod points;

#[cfg(all(
    target_os = "zkvm",
    target_vendor = "succinct",
    target_arch = "riscv32"
))]
fn msm_zkvm(gs: &[[u64; 8]], es: impl IntoIterator<Item = [u32; 8]>) -> Option<[u8; 64]> {
    #![allow(clippy::assertions_on_constants)]
    use std::mem::{align_of, size_of};

    extern "C" {
        fn syscall_bn254_add(p: *mut u32, q: *const u32);
        fn syscall_bn254_double(p: *mut u32);
    }

    fn trans(x: &[u64; 8]) -> &[u32; 16] {
        // SAFETY: Per const assertions above.
        unsafe { &*(x as *const _ as *const _) }
    }

    fn bn254_add(p: &mut [u32; 16], q: &[u32; 16]) {
        unsafe { syscall_bn254_add(p.as_mut_ptr(), q.as_ptr()) }
    }

    fn bn254_double(p: &mut [u32; 16]) {
        unsafe { syscall_bn254_double(p.as_mut_ptr()) }
    }

    fn bn254_mul(g: &[u32; 16], e: &[u32; 8]) -> Option<[u32; 16]> {
        let mut r: Option<[u32; 16]> = None;
        for i in (0..254).rev() {
            let (word, bit) = (i / 32, i % 32);

            if let Some(r) = &mut r {
                bn254_double(r);
            }

            if e[word] >> bit & 1 == 0 {
                continue;
            }

            match &mut r {
                Some(r) => bn254_add(r, g),
                None => r = Some(*g),
            }
        }
        r
    }

    // Sanity checks to ensure casting is safe.
    const _: () = assert!(std::cfg!(target_endian = "little"));
    const _: () = assert!(size_of::<[u64; 8]>() == size_of::<[u32; 16]>());
    const _: () = assert!(size_of::<[u32; 16]>() == size_of::<[u8; 64]>());
    const _: () = assert!(align_of::<[u64; 8]>() >= align_of::<[u32; 16]>());
    const _: () = assert!(align_of::<[u32; 16]>() >= align_of::<[u8; 64]>());

    // SAFETY: Per assertions above.
    let gs: &[[u32; 16]] = unsafe { &*(gs as *const _ as *const _) };
    let mut r: Option<[u32; 16]> = None;

    for (g, e) in gs.iter().zip(es.into_iter()) {
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

#[derive(Debug)]
pub enum Error {
    BlobEmpty,
    BlobTooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BlobEmpty => write!(f, "blob is empty"),
            Error::BlobTooLarge => write!(f, "blob is too large"),
        }
    }
}

impl std::error::Error for Error {}

/// Computes the commitment of a blob of data.
///
/// Inserts padding as per EigenDA's [blob serialization requirements].
/// Empty blobs and blobs larger than [`MAX_BLOB_SIZE`] return an error.
/// All other blobs return a 64-byte commitment. A zero commitment is
/// encoded as a 64-byte array of zeros.
///
/// [blob serialization requirements]: https://docs.eigenlayer.xyz/eigenda/integrations-guides/dispersal/api-documentation/blob-serialization-requirements
pub fn commit(xs: &[u8]) -> Result<[u8; 64], Error> {
    commit_(xs).map(|x| x.unwrap_or([0; 64]))
}

pub const MAX_BLOB_SIZE: usize = points::G1_EVALS[points::G1_EVALS.len() - 1].len() * 31;

fn blob_to_padded_le_chunks(
    xs: &[u8],
) -> Result<(&'static [[u64; 8]], impl Iterator<Item = [u8; 32]> + '_), Error> {
    if xs.is_empty() {
        return Err(Error::BlobEmpty);
    }

    if xs.len() > MAX_BLOB_SIZE {
        return Err(Error::BlobTooLarge);
    }

    let it = xs.chunks(31).map(|x| {
        let mut buf = [0; 32];
        buf[1..x.len() + 1].copy_from_slice(x);
        buf.reverse();
        buf
    });
    let l = xs.len().div_ceil(31).next_power_of_two().trailing_zeros() as usize;

    Ok((points::G1_EVALS[l], it))
}

#[cfg(all(
    target_os = "zkvm",
    target_vendor = "succinct",
    target_arch = "riscv32"
))]
#[inline]
fn commit_(xs: &[u8]) -> Result<Option<[u8; 64]>, Error> {
    #[inline]
    fn to_rv32_limb(x: [u8; 32]) -> [u32; 8] {
        let mut r = [0u32; 8];
        for i in 0..8 {
            r[i] = u32::from_le_bytes(x[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        r
    }
    let (gs, it) = blob_to_padded_le_chunks(xs)?;
    let es = it.map(to_rv32_limb);
    Ok(msm_zkvm(gs, es))
}

#[cfg(not(all(
    target_os = "zkvm",
    target_vendor = "succinct",
    target_arch = "riscv32"
)))]
#[inline]
fn commit_(xs: &[u8]) -> Result<Option<[u8; 64]>, Error> {
    use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
    use ark_ec::AffineRepr;
    use ark_ec::{CurveGroup as _, VariableBaseMSM as _};
    use ark_ff::{BigInt, BigInteger, PrimeField};

    let (gs, it) = blob_to_padded_le_chunks(xs)?;

    let es = it
        .map(|x| Fr::from_le_bytes_mod_order(&x))
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
