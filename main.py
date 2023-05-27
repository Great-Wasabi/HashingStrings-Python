import hashlib

def hash_string_sha224(string):
    hash_object = hashlib.sha224(string.encode())
    hashed_string = hash_object.hexdigest()
    return hashed_string

def hash_string_sha256(string):
    hash_object = hashlib.sha256(string.encode())
    hashed_string = hash_object.hexdigest()
    return hashed_string

def hash_string_sha384(string):
    hash_object = hashlib.sha384(string.encode())
    hashed_string = hash_object.hexdigest()
    return hashed_string

def hash_string_sha512(string):
    hash_object = hashlib.sha512(string.encode())
    hashed_string = hash_object.hexdigest()
    return hashed_string

def hash_string_with_sha2(string):
    sha224_hash = hash_string_sha224(string)
    sha256_hash = hash_string_sha256(string)
    sha384_hash = hash_string_sha384(string)
    sha512_hash = hash_string_sha512(string)
    return sha224_hash, sha256_hash, sha384_hash, sha512_hash

# Example usage
string_to_hash = "PASSWORD"
sha224_hash, sha256_hash, sha384_hash, sha512_hash = hash_string_with_sha2(string_to_hash)
print("PASSWORD(###-###):", string_to_hash)
print("PASSWORD(SHA-224):", sha224_hash)
print("PASSWORD(SHA-256):", sha256_hash)
print("PASSWORD(SHA-384):", sha384_hash)
print("PASSWORD(SHA-512):", sha512_hash)
