from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# RSA
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


def encrypt_rsa(aes_key, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    # enc_aes is a str type variable
    return enc_aes_key.decode('latin-1')


def decrypt_rsa(enc_aes_key, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key.encode('latin-1'))
    # aes_key is bytes type variable
    return aes_key


# AES
def generate_aes_key():
    aes_key = get_random_bytes(16)
    return aes_key


def encrypt_aes(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    enc_mssge = [x for x in (cipher.nonce, tag, ciphertext)]
    # enc_mssge is a lists
    return enc_mssge


def decrypt_aes(enc_mssge, aes_key):
    nonce, tag, ciphertext = enc_mssge[0], enc_mssge[1], enc_mssge[2]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
    message = cipher.decrypt_and_verify(ciphertext, tag)
    return message.decode()

# RSA Digital Signature


def rsa_ds_signer(aes_key, rsa_priv_key):
    message = aes_key
    h = SHA256.new(message)
    signature = pkcs1_15.new(RSA.import_key(rsa_priv_key)).sign(h)
    return signature.decode('latin-1')


def rsa_ds_verifier(aes_key, signature, rsa_pub_key):
    message = aes_key
    h = SHA256.new(message)
    try:
        pkcs1_15.new(RSA.import_key(rsa_pub_key)).verify(
            h, signature.encode('latin-1'))
        print("verification sucess ", flush=True)
        return True
    except ValueError:
        return False


def sha_md_create(value):
    return SHA256.new(str(value).encode())
