import ctypes
import struct

# The encrypted data
enc_flag = b"\xe9\xf2\xe5\xb9A\xb3\xcfW\xbdS2J\x19\x1a\xf5E\x95!z\xeb8b\x92K\xc8\xae\xc9\x82b@\xa4!ro\xa2\xa3\xdau'\xa0\x1bG5ER\xb3?E\xac\xb3\xdd\xbd\xe9|k\xcd\x00\xb6\xbc\x1c;\xae\xda\x92\xb2\xba\xbe\xf2\xd2M\xcf\xa6\xa5\xf3\xe7F\xdb\xc5\xfet\x15\xca\\.eN6\x08"

# --- Helper Functions (Confirmed from assembly and C decompilation) ---

def ror_byte(val, shift):
    """Performs a right bitwise rotation on a byte."""
    val &= 0xff
    shift &= 7
    return ((val >> shift) | (val << (8 - shift))) & 0xff

def rol_byte(val, shift):
    """Performs a left bitwise rotation on a byte."""
    val &= 0xff
    shift &= 7
    return ((val << shift) | (val >> (8 - shift))) & 0xff

def rot13(c_val):
    """Performs the ROT13 cipher."""
    if ord('a') <= c_val <= ord('m') or ord('A') <= c_val <= ord('M'):
        return c_val + 13
    if ord('n') <= c_val <= ord('z') or ord('N') <= c_val <= ord('Z'):
        return c_val - 13
    return c_val

def smul32(a, b):
    """Performs signed 32-bit multiplication."""
    return ctypes.c_int32(ctypes.c_int32(a).value * ctypes.c_int32(b).value).value

def rol_dword(val, shift):
    """Performs a left bitwise rotation on a 32-bit dword."""
    val = ctypes.c_uint32(val).value
    shift &= 31
    return ctypes.c_uint32((val << shift) | (val >> (32 - shift))).value

def ror_dword(val, shift):
    """Performs a right bitwise rotation on a 32-bit dword."""
    val = ctypes.c_uint32(val).value
    shift &= 31
    return ctypes.c_uint32((val >> shift) | (val << (32 - shift))).value

def prng(p1):
    """The finalized, accurate PRNG function."""
    uval = ctypes.c_int32(p1).value
    c1, c2, c3, c4 = -0x179fefe9, -0x655bab11, -0x56b23731, -0x25be3b7a
    
    prod1 = smul32(uval, c1)
    rot1 = rol_dword(prod1, 13)
    res1 = smul32(prod1 ^ rot1, c2)

    rot2 = ror_dword(res1, 5)
    res2 = smul32(res1 ^ rot2, c3)

    rot3 = rol_dword(res2, 24)
    res3 = smul32(res2 ^ rot3, c4)
    
    rot4 = ror_dword(res3, 17)
    return res3 ^ rot4

# --- Main Decryption Logic ---
def solve():
    flag_len = len(enc_flag)
    
    # Use the provided prefix to generate the correct seed
    prefix = b'IERA'
    seed_int = struct.unpack('<I', prefix)[0]

    # [REVERSE STEP 1]: Undo XOR obfuscation
    keystream = []
    current_key = prng(seed_int)
    for _ in range(flag_len):
        keystream.append(current_key & 0xFF)
        current_key = prng(current_key)
    shuffled_buf = bytearray(enc_flag[i] ^ keystream[i] for i in range(flag_len))

    # [REVERSE STEP 2]: Undo block shuffling
    transformed_buf = bytearray(shuffled_buf)
    shift_state = 0
    for j in range(0, flag_len, 8):
        block_size = min(8, flag_len - j)
        shift_state = (shift_state + 3) % 7 + 1
        block = transformed_buf[j:j+block_size]
        shift_amount = shift_state % block_size
        transformed_buf[j:j+block_size] = block[-shift_amount:] + block[:-shift_amount]

    # [REVERSE STEP 3]: Undo initial character transformation
    plain_buf = bytearray(transformed_buf)
    rot_state = 0
    for i in range(flag_len):
        rot_state = (rot_state + 4) % 7 + 1
        char = plain_buf[i]
        
        # Reverse rotation: even bytes were ROL (->ROR), odd bytes were ROR (->ROL)
        if (i % 2) == 0:
            rotated_char = ror_byte(char, rot_state)
        else:
            rotated_char = rol_byte(char, rot_state)
            
        # Reverse ROT13
        plain_buf[i] = rot13(rotated_char)
        
    final_flag = plain_buf.strip(b'\x20').decode(errors='ignore')
    print(f"Decrypted Flag: {final_flag}")

solve()
