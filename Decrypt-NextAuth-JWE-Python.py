import json
from typing import Any
from Crypto.Protocol.KDF import HKDF # pip install pycryptodome
from Crypto.Hash import SHA256 
from jose import jwe # pip install python-jose

from lib.getEnvironmentVariable import getEnvironmentVariable

def getDerivedEncryptionKey(secret: str) -> Any:
    # Think about including the context in your environment variables.
    context = str.encode("NextAuth.js Generated Encryption Key") 
    return HKDF(
        master=secret.encode(),
        key_len=32,
        salt="".encode(),
        hashmod=SHA256,
        num_keys=1,
        context=context,
    )


def get_token(token: str) -> dict[str, Any]:
    '''
    Get the JWE payload from a NextAuth.js JWT/JWE token in Python

    Steps:
    1. Get the encryption key using HKDF defined in RFC5869
    2. Decrypt the JWE token using the encryption key
    3. Create a JSON object from the decrypted JWE token
    '''
    # Retrieve the same JWT_SECRET which was used to encrypt the JWE token on the NextAuth Server
    jwt_secret = getEnvironmentVariable("JWT_SECRET") # Replace this with your environment variable logic - default: os.environ.get("JWT_SECRET")
    encryption_key = getDerivedEncryptionKey(jwt_secret)
    payload_str = jwe.decrypt(token, encryption_key).decode()
    payload: dict[str, Any] = json.loads(payload_str)
    
    return payload
