import base64
import typing as t

from dataclasses import dataclass
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


def repeat_char_bytes(char: str, length: int) -> bytes:
    return b"".join([char.encode()] * length)


def repeat_key_bytes(key: str, length: int) -> bytes:
    key_length = len(key)
    # for


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
        # results: t.List[ResultType] = top_n_results(cipher_bytes, 15)
        _, _, results = try_single_char_ciphers(cipher_bytes)
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
