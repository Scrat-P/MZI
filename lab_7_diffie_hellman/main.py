from ecdsa.keys import SigningKey


def md5(text):
    from md5 import MD5

    text_hash = MD5().md5(text.encode(), hex_result=True)
    return text_hash


def sha256(text):
    from hashlib import sha256

    text_hash = sha256(text.encode()).hexdigest()
    return text_hash


def sha512(text):
    from hashlib import sha512

    text_hash = sha512(text.encode()).hexdigest()
    return text_hash


def get_hash(text, hash_func=sha256):
    return hash_func(text)


if __name__ == "__main__":
    alice_key = SigningKey.generate()
    alice_key_private = alice_key.privkey.secret_multiplier
    alice_key_public = alice_key.verifying_key.pubkey.point

    bob_key = SigningKey.generate()
    bob_key_private = bob_key.privkey.secret_multiplier
    bob_key_public = bob_key.verifying_key.pubkey.point

    alice_bob_key = str(alice_key_public * bob_key_private)
    bob_alice_key = str(alice_key_private * bob_key_public)

    print(f"""
        Bob secret key = {bob_key_private}
        Bob public key = {bob_key_public}

        Alice secret key = {alice_key_private}
        Alice public key = {alice_key_public}

        BobSecret * AlicePublic = {alice_bob_key}
        Hash(BobSecret * AlicePublic) = {get_hash(alice_bob_key)}

        AliceSecret * BobPublic = {bob_alice_key}
        Hash(AliceSecret * BobPublic) = {get_hash(bob_alice_key)}

        Keys and hashes equals = {alice_bob_key == bob_alice_key and get_hash(alice_bob_key) == get_hash(bob_alice_key)}
    """)
