import base64

from collections import defaultdict


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
}

freq_dict_norm = {key.lower(): val / 100 for key, val in freq_dict_percent.items()}


def english_language_distance(as_str: str) -> float:
    count_dict = defaultdict(lambda: 0)
    total_count = 0
    for letter in as_str.lower():
        if letter in freq_dict_norm:
            count_dict[letter] += 1
            total_count += 1

    # lets use L1 distance
    score = sum(
        [
            abs((count / total_count) - freq_dict_norm[key])
            for key, count in count_dict.items()
        ]
    )
    return score


def repeat_char_bytes(char: str, length: int) -> bytes:
    return b"".join([char.encode()] * length)


def try_single_char_ciphers(cipher_bytes: bytes):
    scores = {}
    min_score = 2
    min_char = None
    messages = {}
    for char in freq_dict_norm.keys():
        repeated_key_bytes = repeat_char_bytes(char, len(cipher_bytes))
        xored_bytes = xor_bytes(cipher_bytes, repeated_key_bytes)
        xored_str = xored_bytes.decode()
        scores[char] = english_language_distance(xored_str)
        messages[char] = xored_str
        if scores[char] < min_score:
            min_score = scores[char]
            min_char = char

    return min_char, min_score, messages, scores
