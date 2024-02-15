import base64

import pytest

from crypto.set1.utils import (
    blocks,
    check_many_ciphers,
    decrypt_aes_128,
    decrypt_aes_128_ecb,
    decrypt_cipher_bytes,
    decrypt_repeat_key_xor,
    detect_aes_128_ecb,
    encrypt_repeat_key_xor,
    english_language_distance,
    get_repeat_blocks,
    hamming_char,
    hamming_dist,
    hex_to_b64,
    norm_edit_distance,
    repeat_char_bytes,
    repeat_key_bytes,
    top_n_results,
    transposed_block,
    try_single_char_ciphers,
    xor_bytes,
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


def test_english_language_score_with_nonsense():
    bad_message = "\x1844025<{\x16\x18|({720>{:{+4.5?{4={9:845"
    bad_dist = english_language_distance(bad_message)
    assert bad_dist > 0.9


# Challenge 3
def test_single_byte_order_cipher():
    cipher_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    cipher_bytes = bytes.fromhex(cipher_hex)
    results = top_n_results(cipher_bytes, 10)

    for res in results:
        print(f"{res.key} :: {res.distance} :: {res.message}")

    correct_message = "Cooking MC's like a pound of bacon"
    correct_key = "X"
    assert any(
        [res.message == correct_message and res.key == correct_key for res in results]
    )
    # ETAOIN SHRDLU


# Challenge 4
def test_list_of_cipher_str():
    with open("tests/fixtures/challenge_4_codes.txt", "r") as fp:
        cipher_list = fp.readlines()

    cipher_list_stripped = [item.strip("\n") for item in cipher_list]
    results = check_many_ciphers(cipher_list_stripped)
    for res in results[:30]:
        print(f"{res.i} :: {res.key} :: {res.distance} :: {res.message}")

    correct_message = "Now that the party is jumping\n"
    correct_key = "5"
    correct_i = 170
    assert any(
        [
            res.message == correct_message
            and res.key == correct_key
            and res.i == correct_i
            for res in results
        ]
    )


def test_repeat_key_bytes():
    key = "ICE"
    # 73, 67, 69
    assert repeat_key_bytes(key, 9) == "ICEICEICE".encode()
    assert repeat_key_bytes(key, 2) == "IC".encode()
    assert repeat_key_bytes(key, 5) == "ICEIC".encode()


# Challenge 5
def test_repeating_key_xor():
    message = (
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    )
    key = "ICE"
    cipher_bytes = encrypt_repeat_key_xor(key, message)
    correct_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    assert correct_hex == cipher_bytes.hex()


def test_repeating_key_xor_encrypt_decrypt():
    message = "I'm writing my super secret message"
    key = "my-password"
    cipher_bytes = encrypt_repeat_key_xor(key, message)
    cipher_hex = cipher_bytes.hex()
    print(cipher_hex)
    decrypt_message = decrypt_repeat_key_xor(key, cipher_bytes)
    assert decrypt_message == message


def test_hamming_distance():
    str1 = "this is a test"
    str2 = "wokka wokka!!!"
    dist = hamming_dist(str1.encode(), str2.encode())
    assert dist == 37


def test_norm_edit_distance():
    str1 = "this is a test"
    str2 = "wokka wokka!!!"

    _str = str1 + str2
    dist = norm_edit_distance(_str.encode(), key_size=len(str1))
    assert dist <= 1.0


def test_blocks():
    cipher = "this is a test".encode()
    exp_blocks = ["this ", "is a ", "test"]
    for i, block in enumerate(blocks(cipher, 5)):
        assert block == exp_blocks[i].encode()


def test_blocks_no_remainder():
    cipher = "this is a test2".encode()
    exp_blocks = ["this ", "is a ", "test2"]
    for i, block in enumerate(blocks(cipher, 5)):
        assert block == exp_blocks[i].encode()


def test_blocks_empty():
    cipher = "".encode()
    exp_blocks = []
    for i, block in enumerate(blocks(cipher, 5)):
        assert block == exp_blocks[i].encode()


def test_repeat_blocks():
    block = "this ".encode()
    rblocks = get_repeat_blocks(block)
    assert rblocks == [
        "ttttt".encode(),
        "hhhhh".encode(),
        "iiiii".encode(),
        "sssss".encode(),
        "     ".encode(),
    ]


def test_transposed_block():
    cipher = "abababab".encode()
    key_size = 2
    blocks = []
    for block in transposed_block(cipher, key_size):
        blocks.append(block)
    assert blocks == [
        "aaaa".encode(),
        "bbbb".encode(),
    ]


def test_transposed_block2():
    cipher = "abcdefghijklmnop".encode()
    key_size = 3
    blocks = [block for block in transposed_block(cipher, key_size)]
    assert blocks == [
        "adgjmp".encode(),
        "behkn".encode(),
        "cfilo".encode(),
    ]


# Challenge 6
def test_decrypt_file_repeating_key_xor():
    """Understanding why the smallest hamming distance
    gave me the block size.

    From https://crypto.stackexchange.com/questions/8115/repeating-key-xor-and-hamming-distance
    The ciphertext consists of X ^ K and Y ^ K
    where k is the key and X and Y are some english language

    hamming distance is again just xor so, using rules of xor
    (X ^ K) ^ (Y ^ K) == (X ^ Y) ^ (K ^ K) == (X ^ Y) ^ 0 == X ^ Y

    therefore if we pick K correctly the above holds true, we get the equivalent
    score of xoring 2 english language sections which are likely to produce
    a lower hamming distance than 2 randomly distributed sets of bytes.

    Second part involves understanding why using the transposed_block
    method and solving each block independently worked.
    """
    with open("tests/fixtures/challenge_6_encrypted.txt", "r") as fp:
        ciphertext_64 = fp.read()

    cipher_bytes = base64.b64decode(ciphertext_64)
    sorted_results = decrypt_cipher_bytes(cipher_bytes)
    assert len(sorted_results) == 1
    result = sorted_results[0]
    assert result.key == "TermiNator X: Bring the noise"
    assert (
        result.message
        == "I'm bAck and I'm ringin' the bell *A rockin' on the mike while The fly girls yell \nIn ecstasY in the back of me \nWell thaT's my DJ Deshay cuttin' all Them Z's \nHittin' hard and thE girlies goin' crazy \nVanillA's on the mike, man I'm not Lazy. \n\nI'm lettin' my drug kIck in \nIt controls my mouth And I begin \nTo just let it fLow, let my concepts go \nMy pOsse's to the side yellin', GO Vanilla Go! \n\nSmooth 'cause\x00that's the way I will be \nAnD if you don't give a damn, tHen \nWhy you starin' at me \nSO get off 'cause I control thE stage \nThere's no dissin' aLlowed \nI'm in my own phase \nthe girlies sa y they love me\x00and that is ok \nAnd I can daNce better than any kid n' plAy \n\nStage 2 -- Yea the one yA' wanna listen to \nIt's off My head so let the beat play Through \nSo I can funk it up And make it sound good \n1-2-3\x00Yo -- Knock on some wood \nFoR good luck, I like my rhymes\x00atrocious \nSupercalafragilisTicexpialidocious \nI'm an effEct and that you can bet \nI cAn take a fly girl and make hEr wet. \n\nI'm like Samson -- samson to Delilah \nThere's no\x00denyin', You can try to hang\x00\nBut you'll keep tryin' to gEt my style \nOver and over, pRactice makes perfect \nBut noT if you're a loafer. \n\nYou'lL get nowhere, no place, no tIme, no girls \nSoon -- Oh my god, homebody, you probably eAt \nSpaghetti with a spoon! COme on and say it! \n\nVIP. VanIlla Ice yep, yep, I'm comin'\x00hard like a rhino \nIntoxicatIng so you stagger like a winO \nSo punks stop trying and gIrl stop cryin' \nVanilla Ice Is sellin' and you people are\x00buyin' \n'Cause why the freakS are jockin' like Crazy Glue\x00\nMovin' and groovin' trying To sing along \nAll through thE ghetto groovin' this here sOng \nNow you're amazed by the\x00VIP posse. \n\nSteppin' so harD like a German Nazi \nStartleD by the bases hittin' ground\x00\nThere's no trippin' on mine\x0c I'm just gettin' down \nSparKamatic, I'm hangin' tight liKe a fanatic \nYou trapped me Once and I thought that \nYou Might have it \nSo step down aNd lend me your ear \n'89 in mY time! You, '90 is my year. *\nYou're weakenin' fast, YO! And I can tell it \nYour body'S gettin' hot, so, so I can sMell it \nSo don't be mad and Don't be sad \n'Cause the lyriCs belong to ICE, You can calL me Dad \nYou're pitchin' a fIt, so step back and endure \nlet the witch doctor, Ice, do\x00the dance to cure \nSo come uP close and don't be square \nyou wanna battle me -- AnytimE, anywhere \n\nYou thought thaT I was weak, Boy, you're deaD wrong \nSo come on, everybodY and sing this song \n\nSay --\x00Play that funky music Say, gO white boy, go white boy go *play that funky music Go whiTe boy, go white boy, go \nLay\x00down and boogie and play thaT funky music till you die. \n*Play that funky music Come oN, Come on, let me hear \nPlay\x00that funky music white boy yOu say it, say it \nPlay that Funky music A little louder nOw \nPlay that funky music, whIte boy Come on, Come on, ComE on \nPlay that funky music \n"
    )


# Challenge 7 decrypt cipher encrypted with AES-128-ECB given key
def test_decrypt_aes_128():
    with open("tests/fixtures/challenge_7_encrypted.txt") as fp:
        ciphertext_64 = fp.read()

    cipher_bytes = base64.b64decode(ciphertext_64)
    key = "YELLOW SUBMARINE".encode("utf-8")
    message_bytes = decrypt_aes_128(cipher_bytes, key)
    message = message_bytes.decode("utf-8")
    assert (
        message
        == "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
    )


# Challenge 8 decrypt
def test_detect_aes_in_ecb_mode():
    with open("tests/fixtures/challenge_8_encrypted.txt") as fp:
        candidate_str_64_list = fp.readlines()

    candidates_bytes_list = [bytes.fromhex(hex) for hex in candidate_str_64_list]

    potential = detect_aes_128_ecb(candidates_bytes_list)
    assert len(potential) == 1
