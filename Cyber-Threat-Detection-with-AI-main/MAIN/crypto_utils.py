from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import os

class CryptoManager:
    def __init__(self, keys_dir="keys/"):
        self.keys_dir = keys_dir
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)
            
        self.private_key_path = os.path.join(keys_dir, "private.pem")
        self.public_key_path = os.path.join(keys_dir, "public.pem")
        
        if not os.path.exists(self.private_key_path):
            self._generate_keys()
        else:
            self._load_keys()

    def _generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Save private key
        with open(self.private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open(self.public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        self.private_key = private_key
        self.public_key = public_key

    def _load_keys(self):
        with open(self.private_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        with open(self.public_key_path, "rb") as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def encrypt(self, data: bytes) -> bytes:
        if isinstance(data, str):
            data = data.encode()
            
        encrypted = self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        decoded = base64.b64decode(encrypted_data)
        decrypted = self.private_key.decrypt(
            decoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted 