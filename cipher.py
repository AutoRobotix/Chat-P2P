from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

import os

class AES:

    def derive_key(self, password:str, salt:bytes):
        """Deriva una chiave a 256 bit dalla password."""
        # Deriviamo una chiave fissa dalla password con l'uso di salt casuali
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=4,
            memory_cost=256,
            lanes=2
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt(self, key, data:bytes) -> bytes:
        data = data
        iv = os.urandom(12)
        ciphertext = AESGCMSIV(key).encrypt(iv, data, None)
        encrypted_data = iv + ciphertext
        return encrypted_data

    def decrypt(self, key, data:bytes) -> bytes:
        iv, ciphertext = data[:12], data[12:]
        decrypted = AESGCMSIV(key).decrypt(iv, ciphertext, None)
        return decrypted
    
class ECC:

    def gen_keypair():
        privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pubkey = privkey.public_key()

        # Serializzazione ottimizzata per la chiave pubblica (formato compresso)
        privkey = privkey.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pubkey = pubkey.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.CompressedPoint
        )
        return privkey, pubkey
    
    def gen_sharedkey(self, privkey: bytes, peer_pubkey: bytes):
        privkey = serialization.load_der_private_key(privkey, password=None, backend=default_backend())
        # Caricamento della chiave pubblica in formato compresso
        peer_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pubkey)
        sharedkey = privkey.exchange(ec.ECDH(), peer_pubkey)
        #delete ephemeral keys
        return sharedkey

    def sign(self, signkey: bytes, data: bytes) -> bytes:
        signkey = serialization.load_der_private_key(signkey, password=None, backend=default_backend())
        signature = signkey.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify(self, verikey: bytes, signature: bytes, data: bytes) -> bool:
        # Caricamento della chiave pubblica in formato compresso
        verikey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), verikey)
        try:
            verikey.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False