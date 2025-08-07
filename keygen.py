from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def write_to_file(filename, content):
    f = open(filename, "wb")
    f.write(content)
    f.close()


x = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)


public_key = x.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

private_key = x.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

write_to_file("public_key", public_key)
write_to_file("private_key", private_key)
