use starknet_crypto::poseidon_hash_many;
use starknet_crypto::Felt;

const FELT_LEN: usize = 32;

/// Computes Poseidon hash of two 32-byte little-endian inputs. Writes 32-byte LE output to out_ptr.
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn starknet_crypto_poseidon_hash_2(
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
    let result = poseidon_hash_many([&x, &y]);
    let out = result.to_bytes_le();
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), out_ptr, FELT_LEN);
    }
    0
}

/// Computes Poseidon hash of many Felts. inputs_ptr points to count*32 bytes (LE).
/// Writes 32-byte LE output to out_ptr. Returns 0 on success.
#[no_mangle]
pub extern "C" fn starknet_crypto_poseidon_hash_many(
    inputs_ptr: *const u8,
    count: usize,
    out_ptr: *mut u8,
) -> i32 {
    if inputs_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    if count == 0 {
        return -2;
    }
    let slice = unsafe { std::slice::from_raw_parts(inputs_ptr, count * FELT_LEN) };
    let felts: Vec<Felt> = slice
        .chunks_exact(FELT_LEN)
        .map(|chunk| {
            let arr: [u8; FELT_LEN] = chunk.try_into().unwrap_or([0u8; FELT_LEN]);
            Felt::from_bytes_le_slice(&arr)
        })
        .collect();
    let refs: Vec<&Felt> = felts.iter().collect();
    let result = poseidon_hash_many(refs);
    let out = result.to_bytes_le();
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), out_ptr, FELT_LEN);
    }
    0
}
