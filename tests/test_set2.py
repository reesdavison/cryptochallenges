import base64
import random
from collections import Counter
from typing import Optional

from crypto.pkcs7_padding import pkcs7_pad
from crypto.set1.utils import (
    blocks,
    decrypt_aes_128_cbc,
    detect_block_cipher_mode,
    encrypt_aes_128_cbc,
    encryption_oracle,
    get_block,
    rand_bytes,
    reverse_blocks,
    split_bytes_by_length,
)


# Challenge 9
def test_pkcs7_pad():
    _bytes = b"YELLOW SUBMARINE"
    block_length = 20
    pad_bytes = pkcs7_pad(_bytes, block_length)
    assert pad_bytes == b"YELLOW SUBMARINE\x04\x04\x04\x04"


def test_reverse_blocks():
    _bytes = b"YELLOW SUBMARINE"
    reverse = b"".join(list(reverse_blocks(_bytes, size=2)))
    assert reverse == b"NERIMAUB SOWLLYE"


# Challenge 10
def test_decrypt_xor_cbc():
    # key is of length 16 bytes
    key = b"YELLOW SUBMARINE"
    iv = b"0" * 16

    with open("tests/fixtures/challenge_10_encrypted.txt", "r") as fp:
        ciphertext_64 = fp.read()

    cipher_bytes = base64.b64decode(ciphertext_64)

    decrypted = decrypt_aes_128_cbc(cipher_bytes, key=key, iv=iv)
    assert b"Play that funky music white boy" in decrypted
    encrypted = encrypt_aes_128_cbc(decrypted, key=key, iv=iv)
    decrypted = decrypt_aes_128_cbc(encrypted, key=key, iv=iv)
    assert b"Play that funky music white boy" in decrypted


# Challenge 11
def test_detect_aes_128_mode():
    with open("tests/fixtures/challenge_10_encrypted.txt", "r") as fp:
        ciphertext_64 = fp.read()

    cipher_bytes = base64.b64decode(ciphertext_64)
    assert detect_block_cipher_mode(cipher_bytes) == "cbc"

    # plaintext = b"foobarbazbamblambamolamoramo play that funky music white boy" * 100
    # plaintext = "hello forwhffqhyghello fo".encode()
    plaintext = "asdfghjkasdfghjkasdfghjkasdfghjk".encode() * 2

    num_correct = 0
    for i in range(200):
        key = rand_bytes(16)
        choice = ("ecb", "cbc")[i % 2]
        cipher_text = encryption_oracle(
            message=plaintext, key=key, choice_override=choice
        )
        detection = detect_block_cipher_mode(cipher_text)
        correct = detection == choice
        if correct:
            num_correct += 1

    assert num_correct == 200


# Challenge 12
def test_byte_at_a_time_ecb_decryption_simple():
    unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    unknown_bytes = base64.urlsafe_b64decode(unknown)

    key = b"YELLOW SUBMARINE"

    results = []
    for i in range(2, 128, 2):
        message = b"A" * 60
        cipher_text = encryption_oracle(
            message=message,
            key=key,
            choice_override="ecb",
            use_rand_bytes=False,
        )

        all_blocks = list(blocks(cipher_text, size=i))
        counter = Counter(all_blocks)
        gt_1 = [val > 1 for val in counter.values()]
        if any(gt_1):
            results.append(i)

    block_size = max(results)
    assert block_size == 16
    detection = detect_block_cipher_mode(cipher_text)
    assert detection == "ecb"

    # in our message through oracle function we have
    # 5-10rand bytes + mymessage + unknownmessage + 5-10rand bytes

    # Question 14 suggests with this easy version so
    # we ignore the random bytes at the start
    # and deal with that later

    # AAAA,AAA?
    # AAAA,AAA? let's say first letter is a H, we supply 7 A's, byte dict AAAA,AAA?
    # AAAA,AAH? now if we provide 6 A's, we can form byte dict against AAAA,AAH?
    # AAAA,AHE? provide 5 A's, byte dict AAAA,AHE? -> return L

    # At some point
    # HELL,OWOR provide 0 A's, byte dict HELL,OWO? -> return R
    # to form my byte dict I supply first LLOW,ORL?
    # AAAA,AAHE LLOW,ORLD provide 7 A's but look at the 2nd byte AAAA,AAAH ELLO,WOR?

    # so get_byte_dict needs to take all the previous 7 letters padded with A's if less

    # get_byte_dict(seven_bytes="AAAA,AAA") -> 7A's block0, H
    # get_byte_dict(seven_bytes="AAAA,AAH") -> 6A's block0, E
    # get_byte_dict(seven_bytes="AAAA,AHE") -> 5A's block0, L
    # get_byte_dict(seven_bytes="AAAA,HEL") -> 4A's block0, L
    # get_byte_dict(seven_bytes="AAAH,ELL") -> 3A's block0, O
    # get_byte_dict(seven_bytes="AAHE,LLO") -> 2A's block0, W
    # get_byte_dict(seven_bytes="AHEL,LOW") -> 1A's block0, O
    # get_byte_dict(seven_bytes="HELL,OWO") -> 0A's block0, R
    # get_byte_dict(seven_bytes="ELLO,WOR") -> 7A's block1, L
    # get_byte_dict(seven_bytes="LLOW,ORL") -> 6A's block1, D

    block_size = 16

    def get_next_byte(num_a: int, check_block: int, byte_dict) -> Optional[bytes]:
        crafted_input = b"A" * num_a
        cipher_text = encryption_oracle(
            message=crafted_input + unknown_bytes,
            key=key,
            choice_override="ecb",
            use_rand_bytes=False,
        )
        try:
            return byte_dict[
                get_block(cipher_text, size=block_size, block_num=check_block)
            ]
        except KeyError:
            return None

    def get_byte_dict(prefix: bytes) -> dict:
        byte_dict = {}
        assert len(prefix) == block_size - 1
        for i in range(256):
            test_byte = int.to_bytes(i, length=1, byteorder="big")
            crafted_input = prefix + test_byte
            cipher_text = encryption_oracle(
                message=crafted_input + unknown_bytes,
                key=key,
                choice_override="ecb",
                use_rand_bytes=False,
            )
            byte_dict[get_block(cipher_text, size=block_size, block_num=0)] = test_byte
        return byte_dict

    prefix = b"A" * (block_size - 1)

    num_a = block_size - 1
    check_block = 0
    message = b""

    while True:
        byte_dict = get_byte_dict(prefix=prefix)
        next_byte = get_next_byte(
            num_a=num_a, check_block=check_block, byte_dict=byte_dict
        )
        if next_byte is None:
            break

        message += next_byte
        num_a -= 1
        prefix = prefix[1:] + next_byte

        if num_a == -1:
            num_a = block_size - 1
            check_block += 1

    correct = (
        "Rollin' in my 5.0\n"
        "With my rag-top down so my hair can blow\n"
        "The girlies on standby waving just to say hi\n"
        "Did you stop? No, I just drove by"
    )
    assert message.decode() == correct
