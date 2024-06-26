import base64
import os
import random
import typing as t
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import partial
from itertools import product
from math import ceil

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def hex_to_b64(hex: str) -> str:
    as_bytes = bytes.fromhex(hex)
    return base64.urlsafe_b64encode(as_bytes).decode("utf-8")


def xor_bytes(bytes1: bytes, bytes2: bytes) -> bytes:
    b1_len = len(bytes1)
    b2_len = len(bytes2)
    b3_len = max(b1_len, b2_len)
    integer1 = int.from_bytes(bytes1, byteorder="big")
    integer2 = int.from_bytes(bytes2, byteorder="big")
    integer3 = integer1 ^ integer2
    # length b3_len is number of bytes
    return int.to_bytes(integer3, b3_len, byteorder="big")


def repeat_char_bytes(char: str, length: int) -> bytes:
    return b"".join([char.encode()] * length)


def repeat_key_bytes(key: str, length: int) -> bytes:
    key_length = len(key)
    remainder = length % key_length
    multiples = length // key_length
    return b"".join([key.encode()] * multiples) + key[:remainder].encode()


def encrypt_repeat_key_xor(key: str, message: str) -> bytes:
    bytes_message = message.encode()
    repeat_key = repeat_key_bytes(key, len(bytes_message))
    return xor_bytes(repeat_key, bytes_message)


def decrypt_repeat_key_xor(key: str, cipher: bytes) -> str:
    repeat_key = repeat_key_bytes(key, len(cipher))
    return xor_bytes(repeat_key, cipher).decode()


ALL_HEX_CHARS = [str(i) for i in range(10)] + ["a", "b", "c", "d", "e", "f"]


# a hex string of 2 chars [0-9, a-f] represents 8 bits or one byte!
# ff represent 255
# 00 represents 0
# 0f represents 15
def get_integer(hex_char: str):
    return int.from_bytes(bytes.fromhex(hex_char), byteorder="big")


def get_hex(integer: int):
    # integer should be 0 - 255 representing 1 byte
    return int.to_bytes(integer, 1, byteorder="big").hex()


ALL_HEX_STRINGS = [get_hex(i) for i in range(256)]


# score character frequency, measure number of times integers equal
def hamming_char(bytes1: bytes, bytes2: bytes) -> float:
    """
    Score char
    """
    max_length = max(len(bytes1), len(bytes2))
    start_1 = max_length - len(bytes1)
    start_2 = max_length - len(bytes2)

    score = 0
    for i in range(max_length):
        if i < start_1:
            char1 = 0
        else:
            char1 = bytes1[i - start_1]

        if i < start_2:
            char2 = 0
        else:
            char2 = bytes2[i - start_2]

        if char1 == char2:
            score += 1

    return score


freq_dict_percent = {
    "A": 8.2,
    "B": 1.5,
    "C": 2.8,
    "D": 4.3,
    "E": 13,
    "F": 2.2,
    "G": 2,
    "H": 6.1,
    "I": 7,
    "J": 0.15,
    "K": 0.77,
    "L": 4,
    "M": 2.4,
    "N": 6.7,
    "O": 7.5,
    "P": 1.9,
    "Q": 0.095,
    "R": 6,
    "S": 6.3,
    "T": 9.1,
    "U": 2.8,
    "V": 0.98,
    "W": 2.4,
    "X": 0.15,
    "Y": 2,
    "Z": 0.074,
    " ": 26,
    "__punct__": 8.5,
}

sum_count = sum([val for val in freq_dict_percent.values()])
freq_dict_norm = {
    key.lower(): val / sum_count for key, val in freq_dict_percent.items()
}
other_chars = [chr(i) for i in range(33, 65)]


def english_language_distance(as_str: str) -> float:
    count_dict = defaultdict(lambda: 0)
    total_count = 0
    for letter in as_str.lower():
        if letter in freq_dict_norm:
            count_dict[letter] += 1
            total_count += 1
        elif letter in other_chars:
            count_dict["__punct__"] += 1
            total_count += 1

    if len(count_dict) == 0:
        return 1.0

    # lets use L1 distance
    score = sum(
        [
            abs((count / total_count) - freq_dict_norm[key])
            for key, count in count_dict.items()
        ]
    )
    return score


# def english_language_distance2(as_str: str) -> float:
#     char_list = " etaoinshrdlcumwfgypbvkjxqz"


@dataclass
class ResultType:
    message: str
    distance: float
    key: str


def try_single_char_ciphers(
    cipher_bytes: bytes,
) -> t.Tuple[str, float, t.List[ResultType]]:
    min_score = 2
    min_char = None

    results = []
    for i in range(255):
        char = chr(i)
        repeated_key_bytes = repeat_char_bytes(char, len(cipher_bytes))
        xored_bytes = xor_bytes(cipher_bytes, repeated_key_bytes)
        try:
            xored_str = xored_bytes.decode()
        except UnicodeDecodeError:
            continue
        score = english_language_distance(xored_str)
        results.append(
            ResultType(
                message=xored_str,
                distance=score,
                key=char,
            )
        )
        if score < min_score:
            min_score = score
            min_char = char

    return min_char, min_score, results


def top_n_results(cipher_bytes: bytes, n: int) -> t.List[ResultType]:
    _, _, results = try_single_char_ciphers(cipher_bytes)
    sorted_results = sorted(results, key=lambda x: x.distance)
    k = min(n, len(sorted_results))
    return sorted_results[:k]


@dataclass
class CipherResult:
    i: int
    cipher_str: str
    top_5_results: t.List[ResultType]


@dataclass
class CipherResultItem:
    i: int
    cipher_str: str
    message: str
    distance: float
    key: str


def check_many_ciphers(cipher_list: t.List[str]):
    """Reads in as list of hex encoded strings"""

    results_list = []
    for i, cipher_str in enumerate(cipher_list):
        cipher_bytes = bytes.fromhex(cipher_str)
        results: t.List[ResultType] = top_n_results(cipher_bytes, 5)
        results_list.extend(
            [
                CipherResultItem(
                    i=i,
                    cipher_str=cipher_str,
                    message=res.message,
                    distance=res.distance,
                    key=res.key,
                )
                for res in results
            ]
        )
    return sorted(results_list, key=lambda res: res.distance)


def hamming_dist(str1: bytes, str2: bytes) -> int:
    """Assume same length for now"""
    assert len(str1) == len(str2)
    # A B = Y
    # 0 0 = 0
    # 1 1 = 0
    # 0 1 = 1
    # 1 0 = 1
    # again this is just an XOR, so if we xor and then count
    # the ones in binary we good.
    xored = xor_bytes(str1, str2)
    as_int = int.from_bytes(xored, byteorder="big")
    as_binary_str = bin(as_int)[2:]
    return sum(val == "1" for val in as_binary_str)


def norm_hamming_dist(str1: bytes, str2: bytes) -> float:
    """Hamming distance divided by number of bits to
    return value in range [0, 1]
    """
    return hamming_dist(str1, str2) / (len(str1) * 8)


@dataclass
class EditDistResult:
    key_size: int
    dist: float


def blocks(_bytes: bytes, size: int) -> t.Generator[bytes, None, None]:
    """Return _bytes split into blocks."""
    length = len(_bytes)
    i = 0
    while i + size < length:
        yield _bytes[i : i + size]
        i += size


def get_block(_bytes: bytes, size: int, block_num: int) -> bytes:
    return _bytes[size * block_num : size * (block_num + 1)]


def reverse_blocks(_bytes: bytes, size: int) -> t.Generator[bytes, None, None]:
    length = len(_bytes)
    i = length
    while i - size >= 0:
        yield _bytes[i - size : i]
        i -= size


def norm_edit_distance(cipher: bytes, key_size: int):
    count = 0
    dist = 0
    for block in blocks(cipher, key_size):
        dist += norm_hamming_dist(cipher[:key_size], block)
        dist += norm_hamming_dist(cipher[key_size : key_size * 2], block)
        count += 2
    norm_dist = dist / count
    return norm_dist


def transposed_block(cipher: bytes, key_size: int) -> t.Generator[bytes, None, None]:
    for i in range(key_size):
        pos = i
        block_parts = []
        while pos < len(cipher):
            cipher_int = cipher[pos]
            byte_part = int.to_bytes(cipher_int, 1, byteorder="big")
            block_parts.append(byte_part)
            pos += key_size
        yield b"".join(block_parts)


def get_repeat_blocks(block: bytes) -> t.List[bytes]:
    key_size = len(block)
    rblocks = []
    for i in range(key_size):
        rblocks.append(int.to_bytes(block[i], 1, byteorder="big") * key_size)
    return rblocks


def split_bytes_by_length(_bytes: bytes, length: int = 16) -> t.List[bytes]:
    # length is measured in bytes
    blocks = []
    for pos in range(0, len(_bytes), length):
        final_pos = min(pos + length, len(_bytes))
        blocks.append(_bytes[pos:final_pos])
    return blocks


def decrypt_cipher_bytes(cipher: bytes) -> None:
    """
    1. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    2. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    3. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    4. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    5. Solve each block as if it was single-character XOR. You already have code to do this.
    6. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
    """

    results = []
    for key_size in range(2, 41):
        edit_distance = norm_edit_distance(cipher, key_size)
        results.append(EditDistResult(key_size=key_size, dist=edit_distance))

    key_results = sorted(results, key=lambda res: res.dist)

    get_key = lambda res: res.key
    get_key_size = lambda res: res.key_size
    all_results = []
    for key_size in map(get_key_size, key_results[0:1]):  # Just use the first
        potential_key_parts = []
        for i, block in enumerate(transposed_block(cipher, key_size)):
            block_results: t.List[ResultType] = top_n_results(block, 1)
            potential_key_parts.append(list(map(get_key, block_results)))

        for key_parts in product(*potential_key_parts):
            full_key = "".join(key_parts)
            message = decrypt_repeat_key_xor(full_key, cipher)
            dist = english_language_distance(message)
            all_results.append(
                ResultType(
                    message=message,
                    distance=dist,
                    key=full_key,
                )
            )
    sorted_results = sorted(all_results, key=lambda res: res.distance)
    return sorted_results


def decrypt_aes_128(cipher_text: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    decryptor = cipher.decryptor()
    message = decryptor.update(cipher_text) + decryptor.finalize()
    return message


def encrypt_aes_128(message: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message) + encryptor.finalize()
    return cipher_text


# because ECB returns the same code for the same 16 byte input
# if we split the text into 16 bytes or less and measure repetition...
# 16 bytes is 16 characters in ascii. How many sequences of letters
# are likely to be 16 length long.
# lets do this first and check our assumption we don't get much of
# a distribution and this is more complicated.
# it turns out we do only get 1 result. If the secret is large I
# suppose its likely there are repetition, but in this case its probably
# just an easy case.
# the method works better if we split into smaller numbers of bytes
def detect_aes_128_ecb(cipher_candidates: t.List[bytes]):
    potential_ecb_mode = []

    for i, candidate in enumerate(cipher_candidates):
        blocks = split_bytes_by_length(candidate, 16)
        counter = Counter(blocks)
        gt_1 = [val > 1 for val in counter.values()]
        if any(gt_1):
            potential_ecb_mode.append(i)

    return potential_ecb_mode


def encrypt_aes_128_ecb(message: bytes, key: bytes) -> bytes:
    """Encrypt using AES 128 in ECB mode

    Parameters
    ----------
    message : bytes
        Message in bytes to be encrypted
    key : bytes
        encryption key

    Returns
    -------
    bytes
        Ciphertext
    """
    block_func = encrypt_aes_128
    encrypted_blocks = []
    for block in blocks(message, size=16):
        previous = block_func(block, key)
        encrypted_blocks.append(previous)
    return b"".join(encrypted_blocks)


def decrypt_aes_128_ecb(message: bytes, key: bytes) -> bytes:
    """Decrypt using AES 128 in ECB mode

    Parameters
    ----------
    message : bytes
        Message in bytes to be encrypted
    key : bytes
        encryption key

    Returns
    -------
    bytes
        Ciphertext
    """
    block_func = decrypt_aes_128
    decrypted_blocks = []
    for block in blocks(message, size=16):
        previous = block_func(block, key)
        decrypted_blocks.append(previous)
    return b"".join(decrypted_blocks)


def encrypt_aes_128_cbc(message: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt using AES 128 in CBC mode

    Parameters
    ----------
    message : bytes
        Message in bytes to be encrypted
    iv : bytes
        Initialisation vector to begin CBC mode
    key : bytes
        encryption key
    bytes_block_size : int, optional
        number of bytes for each xor encryption step, by default 16

    Returns
    -------
    bytes
        Ciphertext
    """
    block_func = encrypt_aes_128
    previous = iv
    encrypted_blocks = []
    for block in blocks(message, size=16):
        previous = block_func(xor_bytes(previous, block), key)
        encrypted_blocks.append(previous)
    return b"".join(encrypted_blocks)


"""
encryption
next = aes_en(prev ^ msg_block, key)

aes_de(next, key) = prev ^ msg_block

decryption:
msg_block = aes_de(next, key) ^ prev

"""


def decrypt_aes_128_cbc(
    cipher_bytes: bytes,
    key: bytes,
    iv: t.Optional[bytes] = None,
) -> bytes:
    """Decrypt using AES 128 in CBC mode"""
    bytes_block_size = 16

    if iv is None:
        iv = b"0" * bytes_block_size

    block_func = decrypt_aes_128

    decrypted_blocks = []
    previous = iv
    # this can be parallelised
    for block in blocks(cipher_bytes, size=16):
        decrypted = xor_bytes(block_func(block, key), previous)
        decrypted_blocks.append(decrypted)
        previous = block

    return b"".join(decrypted_blocks)


def rand_bytes(size: int = 16) -> bytes:
    return os.urandom(size)


def encryption_oracle(
    message: bytes,
    key: bytes,
    choice_override: t.Optional[t.Literal["ecb", "cbc"]] = None,
    use_rand_bytes: bool = True,
) -> bytes:
    if use_rand_bytes:
        start_num = random.randint(5, 10)
        end_num = random.randint(5, 10)
        message = rand_bytes(start_num) + message + rand_bytes(end_num)

    func = None
    options = ("ecb", "cbc")
    if choice_override is None:
        choice = options[random.randint(0, 1)]
    else:
        choice = choice_override

    if choice == "cbc":

        def encrypt_aes_128_cbc_rand_iv(_message: bytes, _key: bytes) -> bytes:
            return encrypt_aes_128_cbc(_message, _key, iv=rand_bytes(16))

        func = encrypt_aes_128_cbc_rand_iv
    elif choice == "ecb":
        func = encrypt_aes_128_ecb
    else:
        raise AssertionError("Must be cbc or ecb")

    return func(message, key)


def detect_block_cipher_mode(cipher_text: bytes) -> t.Literal["ecb", "cbc"]:
    poss_list = detect_aes_128_ecb([cipher_text])
    if len(poss_list) > 0:
        return "ecb"
    return "cbc"
