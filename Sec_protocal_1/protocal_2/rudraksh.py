import argparse
import os
from ascon_local import ascon_hash
#from ascon import ascon_hash
from hashlib import shake_256

# === Constants for Rudraksh KEM-poly64 ===
# Based on Table 1 of the paper
n = 64
l = 9
q = 7681
eta = 2
B = 2
d_u = 10         # log2(p) for compressing u
d_v = 3          # log2(t) for compressing v
lenK = 16        # Shared secret size in bytes (128 bits for NIST Level 1 equivalent)
H_out_len = 32   # Output length for pkh hash



def poly_mul_naive(p1, p2):
    # Naive multiplication mod (x^n + 1)
    res = [0] * n
    for i in range(n):
        for j in range(n):
            idx = (i + j) % n
            sign = 1 if i + j < n else -1
            res[idx] = (res[idx] + sign * p1[i] * p2[j]) % q
    return res


# === Polynomial and Vector Arithmetic Helpers ===

def poly_add(p1, p2):
    return [(c1 + c2) % q for c1, c2 in zip(p1, p2)]

def poly_sub(p1, p2):
    return [(c1 - c2 + q) % q for c1, c2 in zip(p1, p2)]



def poly_mul(p1, p2):
    return  poly_mul_naive(p1, p2)




def vector_add(v1, v2):
    return [poly_add(p1, p2) for p1, p2 in zip(v1, v2)]

# A_hat (lxl matrix) * s_hat (l-vector) -> l-vector
def matrix_vector_mul(A_hat, s_hat):
    res = [[0]*n for _ in range(l)]
    for i in range(l):
        for j in range(l):
            prod = poly_mul(A_hat[i][j], s_hat[j])
            res[i] = poly_add(res[i], prod)
    return res

# A_hat^T (lxl matrix) * s_hat (l-vector) -> l-vector
def matrix_T_vector_mul(A_hat, s_hat):
    res = [[0]*n for _ in range(l)]
    for i in range(l):
        for j in range(l):
            prod = poly_mul(A_hat[j][i], s_hat[j])
            res[i] = poly_add(res[i], prod)
    return res

# b_hat (l-vector) . s_hat (l-vector) -> 1 polynomial
def vector_dot_product(b_hat, s_hat):
    res = [0]*n
    for i in range(l):
        prod = poly_mul(b_hat[i], s_hat[i])
        res = poly_add(res, prod)
    return res

# === Sampling and PRF Helpers ===

def gen_A_hat(seed):
    """Generates the lxl matrix A_hat with uniform coefficients from a seed."""
    A_hat = [[([0]*n) for _ in range(l)] for _ in range(l)]
    # Use SHAKE as a PRF to generate a stream of bytes.
    # Each coefficient needs ceil(log2(q)) bits. q=7681 -> 13 bits.
    # We use rejection sampling on 16-bit integers.
    num_bytes_needed = l * l * n * 2 * 2 # Estimate bytes needed, allowing for rejections
    prf_stream = ascon_hash(seed, variant="Ascon-XOF128", hashlength=num_bytes_needed)
    byte_idx = 0
    for i in range(l):
        for j in range(l):
            for k in range(n):
                while True:
                    val = int.from_bytes(prf_stream[byte_idx:byte_idx+2], 'little')
                    byte_idx += 2
                    if val < q:
                        A_hat[i][j][k] = val
                        break
    return A_hat

def cbd(seed, nonce):
    """Centered Binomial Distribution sampler."""
    nonce_bytes = nonce.to_bytes(2, 'little')
    # For eta=2, we need 4 bits per coefficient. n=64 coeffs -> 256 bits = 32 bytes
    buf = ascon_hash(seed + nonce_bytes, variant="Ascon-XOF128", hashlength=n * eta // 2)
    poly = [0] * n
    for i in range(n // 2):
        byte = buf[i]
        # First coefficient from lower 4 bits
        a = bin(byte & 0b11).count('1')
        b = bin((byte >> 2) & 0b11).count('1')
        poly[2*i] = (a - b) % q
        # Second coefficient from upper 4 bits
        a = bin((byte >> 4) & 0b11).count('1')
        b = bin((byte >> 6) & 0b11).count('1')
        poly[2*i+1] = (a - b) % q
    return poly

# === Compression Helpers ===

def compress_poly(p, d):
    return [round(c * (2**d / q)) & ((1 << d) - 1) for c in p]

def decompress_poly(p_comp, d):
    return [round(c_comp * (q / 2**d)) for c_comp in p_comp]

# === Encode / Decode Message ===

def encode(msg_bytes):
    """Encodes a 16-byte message into a polynomial of 64 coefficients."""
    if len(msg_bytes) * 8 != n * B:
        raise ValueError(f"Message must be exactly {n*B//8} bytes long (got {len(msg_bytes)} bytes).")
    bits = ''.join(f'{byte:08b}' for byte in msg_bytes)
    m_poly = [0]*n
    for i in range(n):
        b = int(bits[i*B : i*B+B], 2)
        m_poly[i] = (b * (q // (2**B)))
    return m_poly


def decode(p):
    bits = ""
    for coeff in p:
        val = int((coeff * (1 << B) + q // 2) // q) & ((1 << B) - 1)
        bits += format(val, f'0{B}b')
    return int(bits, 2).to_bytes(n * B // 8, 'big')


# === Hash Helpers ===

def H(data):
    return ascon_hash(data, variant="Ascon-Hash256", hashlength=H_out_len)

def G(seed, msg):
    """Produces K and r from H(pk) and m."""
    # Use Ascon-XOF for variable length output (lenK for key, lenK for randomness)
    h = ascon_hash(b"G" + seed + msg, variant="Ascon-XOF128", hashlength=lenK * 2)
    return h[:lenK], h[lenK:]

# === Serialization Helpers ===
# Note: These are simplified for demonstration. A real-world implementation
# would be more space-efficient.

def serialize_poly_vector(vec):
    res = b""
    for poly in vec:
        for coeff in poly:
            res += coeff.to_bytes(2, 'little', signed=False)
    return res

def deserialize_poly_vector(blob, num_polys):
    vec = []
    bytes_per_poly = n * 2
    for i in range(num_polys):
        poly_bytes = blob[i*bytes_per_poly : (i+1)*bytes_per_poly]
        poly = [int.from_bytes(poly_bytes[j:j+2], 'little', signed=False) for j in range(0, len(poly_bytes), 2)]
        vec.append(poly)
    return vec

def serialize_compressed(u_comp, v_comp):
    """Serializes compressed vectors u and v using efficient bit-packing."""
    # Pack u_comp (l*n coefficients, d_u bits each)
    u_bits = ""
    for poly in u_comp:
        for coeff in poly:
            u_bits += format(coeff, f'0{d_u}b')

    # Pack v_comp (n coefficients, d_v bits each)
    v_bits = ""
    for coeff in v_comp:
        v_bits += format(coeff, f'0{d_v}b')
    
    all_bits = u_bits + v_bits
    
    # Pad with zeros to make the total length a multiple of 8
    padding_len = (8 - len(all_bits) % 8) % 8
    all_bits += '0' * padding_len
    
    return int(all_bits, 2).to_bytes((len(all_bits) // 8), 'big')

def deserialize_compressed(c):
    """Deserializes a bit-packed ciphertext into compressed vectors u and v."""
    all_bits = bin(int.from_bytes(c, 'big'))[2:].zfill(len(c) * 8)
    
    u_bits_len = l * n * d_u
    v_bits_len = n * d_v

    u_bits = all_bits[:u_bits_len]
    v_bits = all_bits[u_bits_len : u_bits_len + v_bits_len]

    # Deserialize u_comp
    u_comp = []
    bit_idx = 0
    for _ in range(l):
        poly = []
        for _ in range(n):
            bits = u_bits[bit_idx : bit_idx + d_u]
            poly.append(int(bits, 2))
            bit_idx += d_u
        u_comp.append(poly)

    # Deserialize v_comp
    v_comp = []
    bit_idx = 0
    for _ in range(n):
        bits = v_bits[bit_idx : bit_idx + d_v]
        v_comp.append(int(bits, 2))
        bit_idx += d_v
        
    return u_comp, v_comp

# === Core KEM Algorithms ===

def PKE_Enc(pk, m, r):
    """Helper for the encryption logic used in Encaps and Decaps."""
    seed_A, b_serialized = pk[:H_out_len], pk[H_out_len:]
    b = deserialize_poly_vector(b_serialized, l)
    
    # Generate matrix A
    A_hat = gen_A_hat(seed_A)

    # Generate secrets and errors from randomness r
    s_prime = [cbd(r, i) for i in range(l)]
    e_prime = [cbd(r, i + l) for i in range(l)]
    e_prime_prime = cbd(r, 2 * l)
    
    # In a real implementation, s' would be transformed to NTT domain.
    # Here we simulate it by using coefficient-wise multiplication.
    # u = INTT(A_hat^T . s'_hat) + e'
    u = matrix_T_vector_mul(A_hat, s_prime)
    u = vector_add(u, e_prime)

    # v = INTT(b_hat^T . s'_hat) + e'' + Encode(m)
    v = vector_dot_product(b, s_prime)
    v = poly_add(v, e_prime_prime)
    v = poly_add(v, encode(m))

    u_comp = [compress_poly(p, d_u) for p in u]
    v_comp = compress_poly(v, d_v)
    
    return serialize_compressed(u_comp, v_comp)

def keygen():
    seed_A = os.urandom(H_out_len)
    d = os.urandom(H_out_len) # Seed for s and e

    A_hat = gen_A_hat(seed_A)
    s = [cbd(d, i) for i in range(l)]
    e = [cbd(d, i + l) for i in range(l)]

    # b = As + e
    b = matrix_vector_mul(A_hat, s)
    b = vector_add(b, e)

    pk = seed_A + serialize_poly_vector(b)
    pkh = H(b"pk" + pk)
    z = os.urandom(lenK)
    sk = serialize_poly_vector(s) + z + pkh
    return pk, sk

def encaps(pk):
    m = os.urandom(lenK)
    pkh = H(b"pk" + pk)
    K, r = G(pkh, m)
    c = PKE_Enc(pk, m, r)
    return c, K

def decaps(c, sk, pk):
    s_bytes_len = l * n * 2
    s_serialized = sk[:s_bytes_len]
    z = sk[s_bytes_len : s_bytes_len + lenK]
    pkh = sk[s_bytes_len + lenK:]
    s = deserialize_poly_vector(s_serialized, l)

    u_comp, v_comp = deserialize_compressed(c)
    u = [decompress_poly(p, d_u) for p in u_comp]
    v = decompress_poly(v_comp, d_v)
    us_prod = vector_dot_product(u, s)
    m_prime_poly = poly_sub(v, us_prod)
    m_prime = decode(m_prime_poly)
    K_prime, r_prime = G(pkh, m_prime)
    c_prime = PKE_Enc(pk, m_prime, r_prime)
    if constant_time_compare(c, c_prime):
        return K_prime
    else:
        return H(z + c)[:lenK]

def constant_time_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

def main():
    original = os.urandom(16)
    encoded = encode(original)
    decoded = decode(encoded)
    assert original == decoded, "Mismatch in encode/decode"
   

    parser = argparse.ArgumentParser(description="Rudraksh KEM Implementation")
    subparsers = parser.add_subparsers(dest='command', required=True)
    subparsers.add_parser('keygen', help='Generate a public/private key pair.')
    subparsers.add_parser('encaps', help='Encapsulate a shared secret.')
    subparsers.add_parser('decaps', help='Decapsulate a shared secret.')

    args = parser.parse_args()

    if args.command == 'keygen':
        kem_keygen()
    elif args.command == 'encaps':
        kem_encaps()
    elif args.command == 'decaps':
        kem_decaps()

if __name__ == '__main__':
    main()
