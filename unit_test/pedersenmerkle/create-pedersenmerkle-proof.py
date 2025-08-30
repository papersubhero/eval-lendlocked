import hashlib
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher


# def hash(value: bytes) -> bytes:
#     return hashlib.blake2s(value).digest()

def hash_to_u32(val: bytes) -> str:
    M0 = val.hex()[:128]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    return " ".join(b0)


if __name__ == '__main__':

    hasher = PedersenHasher(b"test")
    original_data = [1337, 7, 1989, 51966, 1234, 9999, 0, 6]
    hashed_leafs = [hasher.hash_bytes(int.to_bytes(leaf, 64, "big")).compress() for leaf in original_data]

    h0 = hasher.hash_bytes(hashed_leafs[0] + hashed_leafs[1]).compress()
    h1 = hasher.hash_bytes(hashed_leafs[2] + hashed_leafs[3]).compress()
    h2 = hasher.hash_bytes(hashed_leafs[4] + hashed_leafs[5]).compress()
    h3 = hasher.hash_bytes(hashed_leafs[6] + hashed_leafs[7]).compress()


    h00 = hasher.hash_bytes(h0 + h1).compress()
    h01 = hasher.hash_bytes(h2 + h3).compress()

    root = hasher.hash_bytes(h00 + h01).compress()

    directionSelector = "1 0 0"

    path = " ".join([hash_to_u32(node) for node in [hashed_leafs[0], h1, h01]])

    print(hash_to_u32(root) + " " + hash_to_u32(hashed_leafs[1]) + " " + directionSelector + " " + path)




# create an instance with personalisation string

# # hash payload
# digest = hasher.hash_bytes(preimage)
# print(digest)
# x:2685288813799964008676827085163841323150845457335242286797566359029072666741,
# y:3621301112689898657718575625160907319236763714743560759856749092648347440543


# original_data = 1337
# hashed_leaf = hashlib.sha256(int.to_bytes(original_data, 64, "big")).digest()
# print("sha256 hash value")
# print(hashed_leaf)

# pedersen_leaf = hasher.hash_bytes(int.to_bytes(original_data, 64, "big"))
# print("pedersen hash value")
# print(pedersen_leaf)
# print(type(pedersen_leaf))

# print("digest")
# digest = pedersen_leaf.compress()
# print(digest)
# print(type(digest))

# print("pedersen witness bytes")
# witness = hasher.gen_dsl_witness_bytes(int.to_bytes(original_data, 64, "big"))
# print(" ".join(witness))


# print("hash to u32")
# print(hash_to_u32(digest))
