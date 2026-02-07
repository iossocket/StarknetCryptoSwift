use starknet_crypto::pedersen_hash;
use starknet_crypto::Felt;

const FELT_LEN: usize = 32;

/// Computes Pedersen hash of two 32-byte little-endian inputs. Writes 32-byte LE output to out_ptr.
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn starknet_crypto_pedersen_hash(
    a_ptr: *const u8,
    b_ptr: *const u8,
    out_ptr: *mut u8,
) -> i32 {
    if a_ptr.is_null() || b_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    let a = unsafe { std::slice::from_raw_parts(a_ptr, FELT_LEN) };
    let b = unsafe { std::slice::from_raw_parts(b_ptr, FELT_LEN) };
    let a_arr: [u8; FELT_LEN] = a.try_into().map_err(|_| ()).unwrap_or([0u8; FELT_LEN]);
    let b_arr: [u8; FELT_LEN] = b.try_into().map_err(|_| ()).unwrap_or([0u8; FELT_LEN]);
    let x = Felt::from_bytes_le_slice(&a_arr);
    let y = Felt::from_bytes_le_slice(&b_arr);
    let result = pedersen_hash(&x, &y);
    let out = result.to_bytes_le();
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), out_ptr, FELT_LEN);
    }
    0
}
