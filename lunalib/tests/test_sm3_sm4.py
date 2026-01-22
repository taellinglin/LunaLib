import pytest

from lunalib.core.sm3 import sm3_digest, sm3_hex, sm3_batch
from lunalib.core.sm4 import (
    sm4_encrypt_block,
    sm4_decrypt_block,
    sm4_encrypt_ecb,
    sm4_decrypt_ecb,
    sm4_encrypt_ctr,
    sm4_decrypt_ctr,
)


def test_sm3_known_vector_abc():
    # Official test vector for SM3("abc")
    expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    assert sm3_hex(b"abc") == expected


def test_sm3_batch_matches_single():
    data = [b"alpha", b"beta", b"gamma"]
    single = [sm3_digest(d) for d in data]
    batch = sm3_batch(data, max_workers=2)
    assert batch == single


def test_sm4_block_vector():
    # Standard SM4 ECB test vector
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
    expected = bytes.fromhex("681edf34d206965e86b3e94f536e4246")

    ciphertext = sm4_encrypt_block(plaintext, key)
    assert ciphertext == expected

    decrypted = sm4_decrypt_block(ciphertext, key)
    assert decrypted == plaintext


def test_sm4_ecb_roundtrip():
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    data = b"lunalib-sm4-ecb-test-data"

    enc = sm4_encrypt_ecb(data, key, use_gpu=True)
    dec = sm4_decrypt_ecb(enc, key, use_gpu=True)
    assert dec == data


def test_sm4_ctr_roundtrip():
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    data = b"lunalib-sm4-ctr-test-data"

    enc = sm4_encrypt_ctr(data, key, iv, use_gpu=True)
    dec = sm4_decrypt_ctr(enc, key, iv, use_gpu=True)
    assert dec == data
