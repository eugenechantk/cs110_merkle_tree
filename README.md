# Merkle Tree Implementation for Python 2.7
Merkle Tree is a data structure where the root of any two child is the hash of the hash values of the children. The Merkle tree is constructed with the hash values of the merkle tree leaves (nodes at the lowest level of the tree)

## Why Merkle Tree
Merkle tree is usually used to proof the integrity of a data set. Since the roots of sub-trees at each level is hashed based on the hash value of the leaves of the sub-tree, any modification of the data of the leaves will result in a different hash value on the root. To spot tampering of data, we just need to cross-check the hash value of the root of the Merkle tree versus that before. If they do not match, that means there is tampering of data.

While is it possible to create a chain of hash values based on the data set, each hash value based on the previous node's hash value, the tree structure of the Merkle tree provide the following benefits:

- It reduces the number of nodes to traverse through in order to check the validity of the data set (instead of traversing through N number of nodes, where N is the number of nodes in the chain, validation using a Merkle tree only requires traversing log N number of nodes
- It requires little memory to perform validation (instead of storing all the data, Merkle tree only concern itself with the hash values of the data, potentially saving a lot of space -- depending on the hash function used)
- Validation can be performed in isolation from the dataset because Merkle tree only needs the hash values to perform validations. This will enhance the security of the application

Merkle Tree is the basis for cryptocurrencies such as bitcoin because it can validate the membership of a specific block at minimal time (time complexity of Merkle tree will be discussed in the later sections) without exposing the data within each block. It is ideal for decentralized systems where individual computer nodes (i.e. miners) may not have the sufficient computing power to linearly validate the membership of blocks, and security to safeguard the dataset.

## Install
Download the zip file from Github.

## Supported Operations
### INSERT
Inserting the data into the Merkle tree, and then building the Merkle tree
*(See add_leaf() and make_tree() in __init__.py)

### GET_MERKLE_ROOT
Returning the Merkle root (the hash value of root of the Merkle tree) when the Merkle tree is built

### PROOF
Perform an audit proof on a specific leaf of the Merkle tree to determine whether there is tampering of data

## Sample Code
### Initializing the Merkle Tree
Before performing any supported operation of the Merkle tree, initialization is needed
```
newTree = MerkleTree()
```
### Building the Merkle Tree
INSERT operations supports either a string or a list of data values to build the Merkle Tree.
```
data_set = ("aa","bb","cc","dd")

#hashing each of the data for Merkle tree building
newTree.add_leaf(data_set)

#building the Merkle tree with the hash values
newTree.make_tree()
```
### Get Merkle Root
To validate whether the current data set has been tampered, we need to retrieve the hash value of the Merkle root, to compare with the hash value of the new Merkle root.
```
newTree.get_merkle_root()
```
### Proof membership of specific leaf
Merkle tree supports audit proof, where you can validate whether a specific data has been tampered. The PROOF operation takes in the position of the leaf that needed validation, and the hash value of that leaf.
```
test_hash = "some 32 bit SHA256 hash value"

#index = the index of the leaf where the test_hash reside; target_hash = the hash value of the data we wish to validate its membership
newTree.proof(newTree.get_proof_index(index),target_hash)
```

## SHA256 Hashing
SHA-2 is a cryptographic hashing protocol developed by the National Security Agency (NSA). It has a number of variations, but for this Merkle tree implementation, the SHA-256 variation is used. The reasons SHA-2 hashing function is used here are:

- It is a one-way hashing function, meaning that people cannot reverse engineer the value of the data using its hash value
- It is widely used in other protocols, such as TLS and SSL, which means it is more robust and secure than other cryptographic hashing functions

## Audit Proof
Audit proof is the way for Merkle tree to validate the membership of certain data in the tree. It validates by rehashing all the dependent nodes related to the data we are checking and comparing with the original hash value of the Merkle root. If they match, then we can validate the membership of that data. If it does not match, we can assume that the dataset has been tampered.

<p align="center">
  <img src="https://a147ae24-a-62cb3a1a-s-sites.googlegroups.com/site/certificatetransparency/log-proofs-work/ct_hash_5.png">
  <br>
  <i>Example Merkle tree, where Audit Proof is performed on data d3</i>
</p>

To rehash the Merkle root, we need to take the following steps:

- Get the hash value of d2 (leaf node c), then hash c and d to give us node j. 
- Get the hash value of node i, then hash i and j to give us the node m
- Finally, get the hash value of node n, then hash m and n to give us the new Merkle root

**get_proof_index()** calculates the node we need to rehash the tree (i.e. node c, i and n)

Once we have gotten the hash values of all the nodes needed to rehash, we can rehash level by level:

- rehash d (the validating data) with c
- rehash (c,d) with i
- rehash ((c,d),i) with n
- rehash (((c,d),i),n) to get the new Merkle root

Finally, we need to compare the new Merkle root with the original Merkle root to validate the data's membership in the Merkle tree.

**proof()** rehashes the Merkle root and compare the new Merkle root with the existing Merkle root

## Complexity
### Time Complexity
#### INSERT
T(N) = 3N (*from **add_leaf()***) + log N * N (*from **make_tree()***)

T(N) = O(N log N), where N is the number of data in the dataset

#### GET_MERKLE_ROOT
T(N) = 3

T(N) = O(1)

#### PROOF
T(N) = C log N (*from **get_proof_index()**, where C is a constant number of operations*) + D log N (*from **proof()**, where D is a constant number of operations*)

T(N) = O(log N), where N is the number of data in the dataset

Merkle tree is very efficient, especially with large amount of data because its operations scales logarithmically, even under the worst case scenario.

### Space complexity
Since the Merkle tree stores the hash value of all the data, the space complexity is O(N), where N is the number of data in the dataset.

It seems like the Merkle tree has the same space complexity compared to the original dataset. However, because it only stores the hash value of the data, and we are using SHA256 hashing function, each data, regardless of its size, has a hash value sized at 32 bits. Therefore, if the average size of individual data in the dataset is larger than 32 bit, the Merkle tree will save space.

## References

(For implementation of the Merkle tree): https://github.com/Tierion/pymerkletools/blob/master/merkletools/__init__.py

(For theory on Audit Proof and the image attached): https://www.certificate-transparency.org/log-proofs-work

(For SHA256 hashing function): https://en.wikipedia.org/wiki/SHA-2

Last Updated: Dec 15 2017 22:45