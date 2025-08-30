# library for signature computation
from znakes.curves import BabyJubJub
from znakes.eddsa import PrivateKey, PublicKey
from znakes.utils import write_signature_for_zokrates_cli
import hashlib
# library for pedersen hash
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher
LOGLEN = 10
# ADDLOGLEN = 10
# FINALLOGLEN = 10
# for computing function time
import time

def hash_to_u32(val: bytes) -> str:
    M0 = val.hex()[:128]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    return " ".join(b0)


if __name__ == "__main__":

    #### signature creation and verification
    # hardcoded original message before hashing it into constant-size msg variable
    raw_msg = "This is my secret message"
    msg = hashlib.sha512(raw_msg.encode("utf-8")).digest()

    keygenstart = time.time()
    # key generation for signature
    sk = PrivateKey.from_rand(curve=BabyJubJub)
    pk = PublicKey.from_private(sk)
    keygenend = time.time()
    print("Key Generation For EDDSA")
    print(keygenend-keygenstart)

    signstart = time.time()
    # signing
    sig = sk.sign(msg)
    signend = time.time()
    print("EDDSA Sign")
    print(signend-signstart)

    veristart = time.time()
    # verification of signature
    is_verified = pk.verify(sig, msg)
    veriend = time.time()
    print("EDDSA Verify")
    print(veriend-veristart)

    path = 'proof_inputs.txt'
    write_signature_for_zokrates_cli(pk, sig, msg, path)

    #### pedersen hash Merkle tree
    # create pedersen hasher
    hasher = PedersenHasher(b"test")

    # translate log length to leaf number
    LEAFNUM = 2**LOGLEN

    # generate original data, i.e., vk
    original_data = []
    for i in range(LEAFNUM):
        original_data.append(i+10000)

    hash_res_lst = []
    path_hash_lst = []
    # first step: hash all the leaves
    hashed_leafs = [hasher.hash_bytes(int.to_bytes(leaf, 64, "big")).compress() for leaf in original_data]
    hash_res_lst.append(hashed_leafs)
    # the first on-path node is always leaf 0
    path_hash_lst.append(hashed_leafs[0])

    for j in range(LOGLEN):
        this_layer_hash_lst = []
        # take the last list of result
        for k in range(len(hash_res_lst[-1])//2):
            this_hash = hasher.hash_bytes(hash_res_lst[-1][2*k] + hash_res_lst[-1][2*k+1]).compress()
            this_layer_hash_lst.append(this_hash)
        hash_res_lst.append(this_layer_hash_lst)
        if j != (LOGLEN-1):
            path_hash_lst.append(this_layer_hash_lst[1])


    # create a directionSelector always starting from 1, i.e., leaf node 0
    directionSelector = "1"
    for l in range(LOGLEN-1):
        directionSelector = directionSelector+" 0"

    proof_tree_path = " ".join([hash_to_u32(node) for node in path_hash_lst])
    root = hash_res_lst[-1][0]

    proof_input = hash_to_u32(root) + " " + hash_to_u32(hashed_leafs[1]) + " " + directionSelector + " " + proof_tree_path

    #### write two parts of input into the same file to pass as parameter for witness generation
    with open(path, "a") as inputfile:
        inputfile.write(" "+proof_input+" "+proof_input+" "+proof_input)
