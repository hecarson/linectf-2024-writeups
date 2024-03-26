# haki-tako-game | LINE CTF 2024

## Initial steps

Reading the provided code, we can see that when we connect to the server,

1. A new random 256-byte PIN and 32-byte AES key are generated,
2. The PIN is put inside a string `b'Your authentication code is..' + pin + b'. Do not tell anyone and you should keep it secret!'`,
3. The resulting plaintext message is encrypted using AES in GCM mode using a new random 12-byte nonce, and
4. The resulting ciphertext, nonce, and tag are given to us.

Afterwards, the server repeatedly accepts inputs in hexadecimal and can provide potentially useful outputs for us.

* If the input length is 512 hex digits or less, equivalent to 256 bytes, then the input is checked against the PIN. If the PIN is correct, then we are given the flag. Whether the PIN is correct or not, the connection is closed.
    * This means that we have only one shot to give the correct PIN per connection, because another connection will have a different random PIN.
* If the input length is less than or equal to `msg_block_len_in_hex+32`, then we are given the result of decrypting the input with AES in CFB mode with the same key generated previously. However, in each block (16 bytes for AES) of the decryption result, the last two bytes are zeroed out.
* Otherwise, if the input length is longer than `msg_block_len_in_hex+32`, then we are given the result of decrypting the input with AES in CBC mode, also with the same key. Here, none of the result is removed.

We need to find some clever way to use the given CFB and CBC decryption oracle to recover the plaintext PIN. But how?

## GCM, CFB, and CBC

Block ciphers such as AES can only operate on fixed-size blocks of messages. Therefore, when encrypting a plaintext that is longer than the block size, a block cipher mode of operation needs to be used, such as GCM, CFB, and CBC. I used this Wikipedia article with excellent diagrams to learn how these modes work (https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation), but I will also give explanations here.

### GCM (Galois/counter mode) encryption

This paper in section 2.3 explains GCM encryption (https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf).

Let
* $IV$ be the initialization vector/nonce,
* $P_i$ the plaintext blocks,
* $C_i$ the ciphertext blocks,
* $Y_i$ the counters for each block,
* $E_K(x)$ the result of encrypting the block $x$ with the key $K$,
* $\mathrm{len}(x)$ the bit length of $x$, and
* $\oplus$ the bitwise XOR operator.

GCM encryption is done by the following formulas:

$$
\begin{align*}
Y_0 &= \begin{cases}
    IV\ ||\ 0^{31} 1 & \text{if } \mathrm{len}(IV) = 96 \\
    \ldots & \text{o.w.}
\end{cases} \\
Y_i &= Y_{i-1} + 1 \\
C_i &= E_K(Y_i) \oplus P_i
\end{align*}
$$

![GCM encryption simplified diagram](images/gcm-encrypt-simple.png)

GCM has other steps related to authenticity that are not described here, but we will see that they are not necessary to decrypt the PIN.

GCM effectively turns the block cipher into a stream cipher by using the block cipher to generate a keystream. As with a stream cipher, the plaintext is bitwise XORed with the keystream to produce the ciphertext.

> [!NOTE]
> Let's define a "block key" to be a result from $E_K$ that is XORed with a plaintext/ciphertext block.

The case where the IV is not 12 bytes has been omitted in the previous formula, since in this challenge, the nonce/IV used in the PIN encryption is 12 bytes. This makes it easy for us to compute the initial counter $Y_0$ value, which will be useful.

### CFB (Cipher feedback) decryption

Let
* $IV$ be the initialization vector,
* $P_i$ the plaintext blocks,
* $C_i$ the ciphertext blocks,
* $E_K(x)$ the result of encrypting the block $x$ with the key $K$, and
* $\oplus$ the bitwise XOR operator.

CFB decryption is done by the following formulas:

$$
\begin{align*}
P_1 &= C_1 \oplus E_K(IV) \\
P_i &= C_i \oplus E_K(C_{i-1})
\end{align*}
$$

![CFB decryption diagram](images/cfb-decrypt.png)

CFB is similar to GCM in how it also effectively turns the block cipher into a stream cipher.

### CBC (Cipher block chaining) decryption

Let
* $IV$ be the initialization vector,
* $P_i$ the plaintext blocks,
* $C_i$ the ciphertext blocks,
* $D_K(x)$ the result of decrypting the block $x$ with the key $K$, and
* $\oplus$ the bitwise XOR operator.

CBC decryption is done by the following formulas:

$$
\begin{align*}
P_1 &= D_K(C_1) \oplus IV \\
P_i &= D_K(C_i) \oplus C_{i-1}
\end{align*}
$$

![CBC decryption diagram](images/cbc-decrypt.png)

Unlike the other two modes, CBC does not turn the block cipher into a stream cipher.

## Using the CFB decryption oracle

In CFB decryption, ciphertext blocks are XORed with the results of $E_K$ blocks. This inspires a clever idea: using CFB decryption, if we set a ciphertext block $C_2$ to be a GCM-encrypted ciphertext block that we want to decrypt, and set the previous ciphertext block $C_1$ to be the correct GCM block counter, then the resulting second plaintext block $P_2$ will be the decrypted block that we wanted.

![CFB decryption attack diagram](images/cfb-decrypt-attack.png)

It is possible for us to compute the correct block counter, because the nonce used in encrypting the PIN message is given to us, and the nonce is used to derive the first counter value $Y_0$.

The block size of AES is 128 bits or 16 bytes. If we run this attack for every 16-byte block in the given ciphertext, then we can recover most of the plaintext containing the PIN.

```py
from pwnlib.tubes.remote import remote
import json

conn = remote("34.146.137.8", 11223)

line = conn.recvline()
info = json.loads(line)
nonce = info["nonce"]
nonce = bytes.fromhex(nonce)
ciphertext = info["ct"]
ciphertext = bytes.fromhex(ciphertext)
```

```py
# PIN is in 17 blocks starting from block 2 (second block)
for block_idx in range(1, 1 + 16 + 1):
    ct_block = ciphertext[block_idx * 16 : (block_idx + 1) * 16]
    # Use block_idx + 2, because last byte of Y_0 is 0x01, and Y_1 is used for the first plaintext block
    block_counter = nonce + (block_idx + 2).to_bytes(4)
    
    # Get partial plaintext block using CFB
    # Null bytes after ct_block are for lengthening the input to make the server give CBC decryption
    input_bytes = block_counter + ct_block + b"\x00" * (len(ciphertext) - 32)
    conn.send(input_bytes.hex().encode())
    line = conn.recvline()
    info = json.loads(line)
    res_hex = info["ret"]
    res = bytes.fromhex(res_hex)

    # Plaintext block is in second block of result
    partial_pt_block = res[16:32]
```

However, a problem is that when we send ciphertext to the server to decrypt using CFB, in each resulting plaintext block, the server replaces the last two bytes of the block with zero bytes. Brute forcing these unknown bytes by putting in PIN guesses is not viable, because there are $2^8 = 256$ possible values per byte, so $256^2 = 65536$ possible values per block, and $65536^{17} \approx 8 \times 10^{81}$ possible guesses, making a simple brute force attack infeasible.

The server does provide another form of decryption using the same key with CBC decryption, and none of the resulting bytes are hidden. Perhaps it can be useful.

## Brute forcing using the CBC decryption oracle

