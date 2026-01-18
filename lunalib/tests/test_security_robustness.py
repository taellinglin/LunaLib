import pytest

from lunalib.core.sm2 import SM2
from lunalib.storage.encryption import EncryptionManager
from lunalib.core.mempool import MempoolManager


def test_sm2_sign_verify_roundtrip():
    sm2 = SM2()
    private_key, public_key = sm2.generate_keypair()
    message = b"lunalib-test-message"

    signature = sm2.sign(message, private_key)
    assert sm2.verify(message, signature, public_key) is True
    assert sm2.verify(b"tampered", signature, public_key) is False


def test_encryption_manager_detects_tamper():
    manager = EncryptionManager()
    payload = "secret-data"
    password = "correct-horse-battery"

    token = manager.encrypt_data(payload, password)
    assert manager.decrypt_data(token, password) == payload

    # Tamper with token
    tampered = token[:-3] + "abc"
    with pytest.raises(Exception):
        manager.decrypt_data(tampered, password)


def test_verify_password_rejects_wrong_password():
    manager = EncryptionManager()
    data = {"value": "hello"}
    password = "pw1"
    encrypted = manager.encrypt_wallet({"private_key": "k", **data}, password)

    assert manager.verify_password(encrypted, password) is True
    assert manager.verify_password(encrypted, "wrong") is False


def test_mempool_rejects_invalid_transaction():
    mempool = MempoolManager(network_endpoints=["https://bank.linglin.art"])

    invalid_tx = {"type": "transaction", "from": "LUN_x", "to": "LUN_y"}
    assert mempool.add_transaction(invalid_tx) is False