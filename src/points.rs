//! Evaluation forms of EigenDA's SRS G1.

use std::include_bytes;

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

const G1_EVAL_00: &[u8] = include_aligned!("../points/g1_ifft_00.bin");
const G1_EVAL_01: &[u8] = include_aligned!("../points/g1_ifft_01.bin");
const G1_EVAL_02: &[u8] = include_aligned!("../points/g1_ifft_02.bin");
const G1_EVAL_03: &[u8] = include_aligned!("../points/g1_ifft_03.bin");
const G1_EVAL_04: &[u8] = include_aligned!("../points/g1_ifft_04.bin");
const G1_EVAL_05: &[u8] = include_aligned!("../points/g1_ifft_05.bin");
const G1_EVAL_06: &[u8] = include_aligned!("../points/g1_ifft_06.bin");
const G1_EVAL_07: &[u8] = include_aligned!("../points/g1_ifft_07.bin");
const G1_EVAL_08: &[u8] = include_aligned!("../points/g1_ifft_08.bin");
const G1_EVAL_09: &[u8] = include_aligned!("../points/g1_ifft_09.bin");
const G1_EVAL_10: &[u8] = include_aligned!("../points/g1_ifft_10.bin");
const G1_EVAL_11: &[u8] = include_aligned!("../points/g1_ifft_11.bin");
const G1_EVAL_12: &[u8] = include_aligned!("../points/g1_ifft_12.bin");
const G1_EVAL_13: &[u8] = include_aligned!("../points/g1_ifft_13.bin");
const G1_EVAL_14: &[u8] = include_aligned!("../points/g1_ifft_14.bin");
const G1_EVAL_15: &[u8] = include_aligned!("../points/g1_ifft_15.bin");
const G1_EVAL_16: &[u8] = include_aligned!("../points/g1_ifft_16.bin");
const G1_EVAL_17: &[u8] = include_aligned!("../points/g1_ifft_17.bin");

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
// lengths are always multiples of 64. Additionally, thanks to the
// alignment, we can further convert `[u8; 64]` to [u64; 8].
//
// Once `slice_as_chunks` is stabilized, this can be simplified
// and made fully safe.

macro_rules! convert {
    ($($eval:expr),* $(,)?) => {
        &[
            $(
                {
                    // Safety preconditions.
                    assert!($eval.len() >= 64);
                    assert!($eval.len() % 64 == 0);

                    // Cast the slice, changing the length
                    // from `&[u8]` to `&[[u8; 64]]`.
                    std::slice::from_raw_parts(
                        $eval.as_ptr() as *const [u64; 8],
                        $eval.len() / 64,
                    )
                },
            )*
        ]
    };
}

/// EigenDA's G1 points in evaluation form. The index at `i` corresponds
/// to the coefficient form of the polynomial of length 2^i. Each element
/// is the little-endian encoding of `x` followed by the little-endian
/// of `y`, each 32 bytes. None of the points are zero.
///
/// Points are stored as arrays of `u64` to allow safe casting from
/// `&[u64; 8]` to `&[u32; 16]` for use with RISC-V based zkVMs like
/// sp1, while also being convenient to use for libraries like Arkworks.
pub const G1_EVALS: &[&[[u64; 8]]] = unsafe {
    convert! {
        G1_EVAL_00,
        G1_EVAL_01,
        G1_EVAL_02,
        G1_EVAL_03,
        G1_EVAL_04,
        G1_EVAL_05,
        G1_EVAL_06,
        G1_EVAL_07,
        G1_EVAL_08,
        G1_EVAL_09,
        G1_EVAL_10,
        G1_EVAL_11,
        G1_EVAL_12,
        G1_EVAL_13,
        G1_EVAL_14,
        G1_EVAL_15,
        G1_EVAL_16,
        G1_EVAL_17,
    }
};
