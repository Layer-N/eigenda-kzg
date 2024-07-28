//! Coefficient forms of EigenDA's SRS G1.

// Trick to control alignment of `include_bytes`.
// https://users.rust-lang.org/t/can-i-conveniently-compile-bytes-into-a-rust-program-with-a-specific-alignment/24049
#[repr(C)]
struct Align<T: ?Sized> {
    _align: [u64; 0],
    bytes: T,
}

macro_rules! include_aligned {
    ($path:literal) => {{
        const ALIGNED: &Align<[u8]> = &Align {
            _align: [],
            bytes: *include_bytes!($path),
        };

        &ALIGNED.bytes
    }};
}

// From the Rustonomicon:
//
// > An array of `[T; N]` has a size of `size_of::<T>() * N` and the
// > same alignment of `T`. Arrays are laid out so that the zero-based
// > `nth` element of the array is offset from the start of the array
// > by `n * size_of::<T>()` bytes.
//
// > Slices have the same layout as the section of the array they slice.
//
// Thus, converting the `&[u8]` to `&[[u8; 64]]` is safe as long as the
// lengths is a multiple of 64. Additionally, thanks to the alignment,
// we can further convert `[u8; 64]` to [u64; 8] or [u32; 16].
//
// Once `slice_as_chunks` is stabilized, this can be simplified
// and made safer.

const G1_COEFF: &[u8] = include_aligned!("../points/g1_coeff.bin");

const _: () = assert!(G1_COEFF.len() >= 64);
const _: () = assert!(G1_COEFF.len() % 64 == 0);
const _: () = assert!(std::mem::align_of::<Align<[u8; 0]>>() == 8);
const _: () = assert!(std::mem::size_of::<[u32; 16]>() == 64);
const _: () = assert!(std::mem::align_of::<[u32; 16]>() <= 8);

#[allow(dead_code)]
pub const G1_COEFF_U8_LE: &[[u8; 64]] = unsafe {
    std::slice::from_raw_parts(G1_COEFF.as_ptr() as *const [u8; 64], G1_COEFF.len() / 64)
};

#[cfg(target_endian = "little")]
#[allow(dead_code)]
pub const G1_COEFF_U32_LE: &[[u32; 16]] = unsafe {
    std::slice::from_raw_parts(G1_COEFF.as_ptr() as *const [u32; 16], G1_COEFF.len() / 64)
};

const _: () = assert!(G1_COEFF_U8_LE.len() == G1_COEFF_U32_LE.len());
