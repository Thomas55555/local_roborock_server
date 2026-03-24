from roborock_local_server.security import AdminSessionManager, hash_password, verify_password


def test_password_hash_round_trip() -> None:
    stored = hash_password("correct horse battery staple", iterations=10_000)

    assert verify_password("correct horse battery staple", stored) is True
    assert verify_password("not-it", stored) is False


def test_admin_session_verification_rejects_tampering() -> None:
    manager = AdminSessionManager(secret="abcdefghijklmnopqrstuvwxyz123456", ttl_seconds=3600)
    token = manager.issue()

    assert manager.verify(token) is not None
    assert manager.verify(token + "tampered") is None

