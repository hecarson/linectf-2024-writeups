from pwnlib.tubes.remote import remote
import json

def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

conn = remote("34.146.137.8", 11223)

line = conn.recvline()
info = json.loads(line)
nonce = info["nonce"]
nonce = bytes.fromhex(nonce)
ciphertext = info["ct"]
ciphertext = bytes.fromhex(ciphertext)

print("nonce", nonce.hex())
print("ciphertext", ciphertext.hex())
print()

num_blocks = len(ciphertext) // 16
plaintext_parts = []
# for block_idx in range(num_blocks):
for block_idx in range(1, 1 + 16 + 1):
    ct_block = ciphertext[block_idx * 16 : (block_idx + 1) * 16]
    block_counter = nonce + (block_idx + 2).to_bytes(4)
    
    # Get partial plaintext block using CFB
    input_bytes = block_counter + ct_block + b"\x00" * (len(ciphertext) - 32)
    conn.send(input_bytes.hex().encode())
    line = conn.recvline()
    info = json.loads(line)
    res_hex = info["ret"]
    res = bytes.fromhex(res_hex)

    partial_pt_block = res[16:32]

    # Brute force full block key using CBC
    # Put multiple trials of block keys into one request for efficiency
    partial_block_key = xor(ct_block, partial_pt_block)[:14]
    block_key = None
    num_trials = 256 ** 2 # 2 unknown bytes
    trials_per_request = 512 // 32 # Max request length is 1024 hex digits -> 512 bytes, 2 16-byte blocks per trial
    num_requests = num_trials // trials_per_request

    for request_idx in range(num_requests):
        if request_idx % 100 == 0:
            print("request idx", request_idx)

        # Make a request that has multiple trial block keys
        # NOTE: could be more efficient by using every block for a trial block key, zero blocks not needed
        input_bytes = bytearray()
        trial_block_keys = []
        for request_trial_idx in range(trials_per_request):
            trial_idx = request_trial_idx + trials_per_request * request_idx
            trial_block_key = partial_block_key + bytes([trial_idx // 256, trial_idx % 256])
            input_bytes.extend([0] * 16)
            input_bytes.extend(trial_block_key)
            trial_block_keys.append(trial_block_key)
        
        conn.send(input_bytes.hex().encode())
        line = conn.recvline()
        info = json.loads(line)
        res_hex = info["ret"]
        res = bytes.fromhex(res_hex)

        # Search decryption result for the correct block counter to find block key
        for request_trial_idx in range(trials_per_request):
            trial_pt_block = res[request_trial_idx * 32 + 16 : (request_trial_idx + 1) * 32]
            if trial_pt_block == block_counter:
                block_key = trial_block_keys[request_trial_idx]
                print("found block key", block_key)
                break
        if block_key != None:
            break

    pt_block = xor(ct_block, block_key)
    print("plaintext block", pt_block)
    plaintext_parts.append(pt_block)

print()
plaintext = b"".join(plaintext_parts)
print("plaintext", plaintext)
print()
pin = plaintext[13 : -3]
print("pin", pin.hex())
print()

conn.send(pin.hex().encode())
line = conn.recvline()
print(line)