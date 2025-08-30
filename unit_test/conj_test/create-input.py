import hashlib

from znakes.curves import BabyJubJub
from znakes.eddsa import PrivateKey, PublicKey
from znakes.utils import write_signature_for_zokrates_cli


def hash(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def hash_to_u32(val: bytes) -> str:
    M0 = val.hex()[:128]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    return " ".join(b0)


if __name__ == "__main__":

    # hardcoded original message before hashing it into constant-size msg variable
    raw_msg = "This is my secret message"
    msg = hashlib.sha512(raw_msg.encode("utf-8")).digest()

    sk = PrivateKey.from_rand(curve=BabyJubJub)
    sig = sk.sign(msg)

    pk = PublicKey.from_private(sk)
    is_verified = pk.verify(sig, msg)
    print(is_verified)

    path = 'conj_inputs.txt'
    write_signature_for_zokrates_cli(pk, sig, msg, path)

    # # Writes the input arguments for verifyEddsa in the ZoKrates stdlib to file.
    # sig_R, sig_S = sig
    # args = [sig_R.x, sig_R.y, sig_S, pk.p.x.n, pk.p.y.n]
    # args = " ".join(map(str, args))

    # M0 = msg.hex()[:64]
    # M1 = msg.hex()[64:]
    # b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    # b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
    # args = args + " " + " ".join(b0 + b1)

    # with open(path, "w+") as file:
    #     for l in args:
    #         file.write(l)

    # hardcoded input with eight leaves
    original_data = [1337, 7, 1989, 51966, 1234, 9999, 0, 6]
    hashed_leafs = [hash(int.to_bytes(leaf, 64, "big")) for leaf in original_data]

    h0 = hash(hashed_leafs[0] + hashed_leafs[1])
    h1 = hash(hashed_leafs[2] + hashed_leafs[3])
    h2 = hash(hashed_leafs[4] + hashed_leafs[5])
    h3 = hash(hashed_leafs[6] + hashed_leafs[7])

    h00 = hashlib.sha256(h0 + h1).digest()
    h01 = hashlib.sha256(h2 + h3).digest()

    root = hashlib.sha256(h00 + h01).digest()

    directionSelector = "1 0 0"

    proof_tree_path = " ".join([hash_to_u32(node) for node in [hashed_leafs[0], h1, h01]])

    proof_input = hash_to_u32(root) + " " + hash_to_u32(hashed_leafs[1]) + " " + directionSelector + " " + proof_tree_path
    print(proof_input)
    ## input list
    # 1. hash tree root
    # 2. the leaf No. 1, to which we prove membership
    # 3. a direction selector to indicate the position of the path on the tree, left is 1, right is 0
    # 4. the nodes on the path, in this case, the leaf node on the left, then the intemidiate nodes on the right

    with open(path, "a") as inputfile:
        inputfile.write(" "+proof_input)
