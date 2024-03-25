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

### GCM

![GCM simplified diagram](images/gcm-simple.png)

GCM has other steps than what is shown in the diagram, but they are not important for this challenge.

As explained in this paper in section 2.3 (https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf), if the nonce/IV is 12 bytes, then the initial value of the counter for block 0 is `IV || 0^31 || 1`, where `||` represents bit concatentation and `0^31` represents 31 0 bits. Since the nonce used in the PIN encryption is 12 bytes, it is easy for us to compute the initial counter value, which will be useful.