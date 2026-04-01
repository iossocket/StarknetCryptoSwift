use starknet_crypto::poseidon_hash;
use starknet_crypto::poseidon_hash_many;
use starknet_crypto::poseidon_hash_single;
use starknet_crypto::Felt;

const FELT_LEN: usize = 32;

fn slice_to_felt(s: &[u8]) -> Felt {
    let arr: [u8; FELT_LEN] = s.try_into().unwrap_or([0u8; FELT_LEN]);
    Felt::from_bytes_le_slice(&arr)
}

fn copy_felt_out(f: Felt, out: *mut u8) {
    let bytes = f.to_bytes_le();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, FELT_LEN);
    }
}

/// Direct Hades: state = [a, b, 2], returns state[0]. Used in StarkNet transaction hash.
/// Returns 0 on success, -1 on null.
#[no_mangle]
pub extern "C" fn starknet_crypto_poseidon_hash(
    a_ptr: *const u8,
    b_ptr: *const u8,
    out_ptr: *mut u8,
) -> i32 {
    if a_ptr.is_null() || b_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    let a = unsafe { std::slice::from_raw_parts(a_ptr, FELT_LEN) };
    let b = unsafe { std::slice::from_raw_parts(b_ptr, FELT_LEN) };
    let x = slice_to_felt(a);
    let y = slice_to_felt(b);
    let result = poseidon_hash(x, y);
    copy_felt_out(result, out_ptr);
    0
}

/// Direct Hades single: state = [value, 0, 1], returns state[0].
/// Returns 0 on success, -1 on null.
#[no_mangle]
pub extern "C" fn starknet_crypto_poseidon_hash_single(
    value_ptr: *const u8,
    out_ptr: *mut u8,
) -> i32 {
    if value_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    let value = unsafe { std::slice::from_raw_parts(value_ptr, FELT_LEN) };
    let x = slice_to_felt(value);
    let result = poseidon_hash_single(x);
    copy_felt_out(result, out_ptr);
    0
}

/// Computes Poseidon hash of two Felts via poseidon_hash_many ([a, b]). Writes 32-byte LE output to out_ptr.
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
    let x = slice_to_felt(a);
    let y = slice_to_felt(b);
    let result = poseidon_hash_many([&x, &y]);
    copy_felt_out(result, out_ptr);
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
    if out_ptr.is_null() {
        return -1;
    }
    if count > 0 && inputs_ptr.is_null() {
        return -1;
    }
    let slice = if count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(inputs_ptr, count * FELT_LEN) }
    };
    let felts: Vec<Felt> = slice
        .chunks_exact(FELT_LEN)
        .map(|chunk| {
            let arr: [u8; FELT_LEN] = chunk.try_into().unwrap_or([0u8; FELT_LEN]);
            Felt::from_bytes_le_slice(&arr)
        })
        .collect();
    let refs: Vec<&Felt> = felts.iter().collect();
    let result = poseidon_hash_many(refs);
    copy_felt_out(result, out_ptr);
    0
}
