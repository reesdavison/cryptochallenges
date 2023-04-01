import pytest

from crypto.set1.utils import (
    hex_to_b64,
    xor_bytes,
    try_single_char_ciphers,
    hamming_char,
    english_language_distance,
    repeat_char_bytes,
)

# Notes on hexadecimal
# --------------------
# a single character [0-9,a-f] represents 4 bits
# each hex char can represent up to number 15
# 2 hex chars represent 8 bits or 1 byte
# f     f
# 15    15
# 1111  1111


# Challenge 1
def test_hex_to_b64():
    hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    correct_encoded_b64 = (
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )
    b64 = hex_to_b64(hex_string)
    assert b64 == correct_encoded_b64


def test_xor_experiments():
    # Truth table XOR
    # -------
    # A B = X
    # -------
    # 0 0 = 0
    # 0 1 = 1
    # 1 0 = 1
    # 1 1 = 0
    # -------

    assert 0 ^ 0 == 0
    assert 0 ^ 1 == 1
    assert 1 ^ 0 == 1
    assert 1 ^ 1 == 0

    # 010 XOR 101 == 111
    assert 2 ^ 5 == 7

    # 000 XOR 111 == 111
    assert 0 ^ 7 == 7

    # 000 XOR 101 == 101
    #   0 XOR 101 == 101 padded to left
    assert 0 ^ 23 == 23

    # 000 XOR 000 == 000
    assert 0 ^ 0 == 0

    # 111 XOR 111 == 000
    assert 7 ^ 7 == 0
    assert 20 ^ 20 == 0

    # rules of XOR
    # a ^ 0 == a
    # a ^ a == 0
    # a ^ a' == 1
    # a ^ 1 == a'

    # 1010 XOR 1111 == 0101
    assert 10 ^ 15 == 5

    # 1010 XOR 0101 == 1111
    assert 10 ^ 5 == 15

    # A XOR 0 == A
    # A XOR A == 0
    # A XOR B == B XOR A    Commutativity
    # (A XOR B) XOR C == A XOR (B XOR C) # [Note 0]
    # (B XOR A) XOR A == B XOR (A XOR A) == B XOR 0 == B

    # [Note 0] Associativity
    # (1000 XOR 0100) XOR 0010 == 1000 XOR (0100 XOR 0010)
    # 1100 XOR 0010 == 1000 XOR 0110
    # 1110 == 1110

    # Thanks to the final proof, how the symmetric encryption
    # (message XOR key) XOR key == message
    # cipher XOR key == message


# Challenge 2
def test_fixed_xor():
    hex_string1 = "1c0111001f010100061a024b53535009181c"
    hex_string2 = "686974207468652062756c6c277320657965"

    bytes1 = bytes.fromhex(hex_string1)
    bytes2 = bytes.fromhex(hex_string2)

    bytes3 = xor_bytes(bytes1, bytes2)

    hex_string3 = bytes3.hex()

    assert hex_string3 == "746865206b696420646f6e277420706c6179"


def test_hamming_char():
    bytes1 = bytes.fromhex("00ff00ff")
    bytes2 = bytes.fromhex("00ff00ff")
    score = hamming_char(bytes1, bytes2)
    assert score == 4


def test_hamming_char_different_len():
    bytes1 = bytes.fromhex("00ff00ff")
    bytes2 = bytes.fromhex("ff00ff00ff")
    score = hamming_char(bytes1, bytes2)
    assert score == 4


def test_hamming_char_diff():
    bytes1 = bytes.fromhex("ff00ff00")
    bytes2 = bytes.fromhex("ff00ff00ff")
    score = hamming_char(bytes1, bytes2)
    assert score == 0


def test_english_language_score():
    test_real = "hello there, how is it going"
    small_distance = english_language_distance(test_real)

    test_garbage = "9wx340t97nwc45087ty43q80vtq30"
    large_distance = english_language_distance(test_garbage)
    assert small_distance < large_distance


# Challenge 3
def test_single_byte_order_cipher():
    cipher_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    cipher_bytes = bytes.fromhex(cipher_hex)

    _, _, messages, scores = try_single_char_ciphers(cipher_bytes)

    for char, message in messages.items():
        print(f"{char} :: {scores[char]} :: {message}")

    breakpoint()

    # ETAOIN SHRDLU
