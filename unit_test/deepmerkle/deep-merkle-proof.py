import hashlib

LOGLEN = 4

def hash(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def hash_to_u32(val: bytes) -> str:
    M0 = val.hex()[:128]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    return " ".join(b0)


if __name__ == '__main__':

    # translate log length to leaf number
    LEAFNUM = 2**LOGLEN

    # generate original data, i.e., vk
    original_data = []
    for i in range(LEAFNUM):
        original_data.append(i+10000)

    hash_res_lst = []
    path_hash_lst = []

    # first step: hash all the leaves
    hashed_leafs = [hash(int.to_bytes(leaf, 64, "big")) for leaf in original_data]
    hash_res_lst.append(hashed_leafs)
    # the first on-path node is always leaf 0
    path_hash_lst.append(hashed_leafs[0])

    for j in range(LOGLEN):
        this_layer_hash_lst = []
        # take the last list of result
        for k in range(len(hash_res_lst[-1])//2):
            this_hash = hash(hash_res_lst[-1][2*k] + hash_res_lst[-1][2*k+1])
            this_layer_hash_lst.append(this_hash)
        hash_res_lst.append(this_layer_hash_lst)
        if j != (LOGLEN-1):
            path_hash_lst.append(this_layer_hash_lst[1])

    

    # h0 = hash(hashed_leafs[0] + hashed_leafs[1])
    # h1 = hash(hashed_leafs[2] + hashed_leafs[3])
    # h2 = hash(hashed_leafs[4] + hashed_leafs[5])
    # h3 = hash(hashed_leafs[6] + hashed_leafs[7])

    # h00 = hash(h0 + h1)
    # h01 = hash(h2 + h3)

    # root = hash(h00 + h01)

    # assert(hash_res_lst[-1][0] == root)
    
    # create a directionSelector always starting from 1, i.e., leaf node 0
    directionSelector = "1"
    for l in range(LOGLEN-1):
        directionSelector = directionSelector+" 0"
    
    # assert(directionSelector == "1 0 0")

    # assert([hashed_leafs[0], h1, h01] == path_hash_lst)
    # print("Yessssss")


    path = " ".join([hash_to_u32(node) for node in path_hash_lst])
    root = hash_res_lst[-1][0]

    print(hash_to_u32(root) + " " + hash_to_u32(hashed_leafs[1]) + " " + directionSelector + " " + path)
