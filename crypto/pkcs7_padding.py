def pkcs7_pad(_bytes: bytes, block_length: int = 8) -> bytes:
    # block length measured in bytes
    # Append the number of bytes of padding to the end of the block
    num_pad = block_length % len(_bytes)
    padding_byte = int.to_bytes(num_pad, 1, byteorder="big")
    return _bytes + padding_byte * num_pad
