//! Coefficient forms of EigenDA's SRS G1.

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

// Trick to control alignment of `include_bytes`.
// https://users.rust-lang.org/t/can-i-conveniently-compile-bytes-into-a-rust-program-with-a-specific-alignment/24049
#[repr(C)]
struct Align<T: ?Sized> {
    _align: [u64; 0],
    bytes: T,
}

macro_rules! include_aligned_as {
    ($path:literal, $ty:ty) => {{
        const ALIGNED: &Align<[u8]> = &Align {
            _align: [],
            bytes: *include_bytes!($path),
        };

        assert!(std::mem::align_of::<Align<[u8; 0]>>() == 8);
        assert!(ALIGNED.bytes.len() % std::mem::size_of::<$ty>() == 0);
        assert!(std::mem::align_of::<$ty>() <= 8);

        let ptr = ALIGNED.bytes.as_ptr() as *const $ty;
        let len = ALIGNED.bytes.len() / std::mem::size_of::<$ty>();

        // SAFETY: The alignment and size of the slice is correct.
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }};
}

#[allow(dead_code)]
#[cfg(target_endian = "little")]
pub const G1_COEFF_STD_U32_LE: &[[u32; 16]] =
    include_aligned_as!("../points/g1_coeff_std.bin", [u32; 16]);

#[allow(dead_code)]
pub const G1_COEFF_MONT_U8_LE: &[[[u8; 32]; 2]] =
    include_aligned_as!("../points/g1_coeff_mont.bin", [[u8; 32]; 2]);

const _: () = assert!(G1_COEFF_MONT_U8_LE.len() == G1_COEFF_STD_U32_LE.len());
