import hashlib

class MerkleTree:
    
    """Initialize the merkle tree by using the reset_tree
    class function"""
    def __init__(self):
        self.reset_tree()
    
    """reset tree with no leaves and no levels"""
    def reset_tree(self):
        self.leaves = list()
        self.levels = None
        #whether the merkle tree is constructed
        self.is_made = False
        
    """
    Purpose: add leaves to the tree by hashing the values
    
    Argument: 
    
    values: str or list
        A list of values needed to be hashed using sha256 hash function
    
    Return:
    
    self.leaves: list
        A list of leaves of hash values of the values parsed into the function
    """
    def add_leaf(self,values):
        self.is_made = False
        """making sure all values are converted into list"""
        if not isinstance(values,tuple) or isinstance(values,list):
            values = [values]
        for item in values:
            """hash individual value using sha256 hash function"""
            item = hashlib.sha256(item).digest()
            item = item.encode('hex')
            self.leaves.append(item)
        return self.leaves
            
    """
    Purpose: Construct the merkle tree
    
    Argument: None
    
    Return:
    
    self.is_made: boolean
        True if the merkle tree is successfully constructed
    """
    def make_tree(self):
        self.is_made = False
        
        """Initialize the levels array with all the leaves hash values"""
        if self.levels is None:
            self.levels = [self.leaves,]
        
        """Recursive function until there is only 1 hash value left
        at the current level (aka Merkle root)"""
        while len(self.levels[0]) > 1:
            next_level = []
            single_leaf = None
            single = 0
            
            """Check if there is an odd number of leaves at this level
            If yes: store the last leaf such that we can append to end of
            all the leaves at this level"""
            if len(self.levels[0])%2 == 1:
                single_leaf = self.levels[0][-1]
                single = 1
            
            """Combine two leaves and hash it again to create a new hash"""
            for i in range(0,len(self.levels[0])-1-single,2):
                combine_hash = hashlib.sha256(hashlib.sha256(self.levels[0][i]+self.levels[0][i+1]).digest()).digest()
                combine_hash = combine_hash.encode('hex')
                next_level.append(combine_hash)
            
            """Append the last single leaf"""
            if single_leaf is not None:
                next_level.append(single_leaf)
            
            """Append the leaves at this level to the top of the tree,
            represented by the levels array"""
            self.levels = [next_level,] + self.levels
            
            """Hash at the next level"""
            self.make_tree()
        
        """Indicating that the Merkle tree is complete"""
        self.is_made = True
        return self.is_made
            
    """
    Purpose: Return the merkle root
    
    Argument: None
    
    Return:
    
    self.levels[0]: str
        the hash value of the root of the merkle tree (aka merkle root)
    """
    def get_merkle_root(self):
        
        """Check if the Merkle tree is made, and the merkle tree
        is not empty"""
        if self.is_made == True:
            if self.levels is not None:
                return self.levels[0]
        else:
            raise ValueError("Merkle tree not built")
            
    """
    Purpose: Getting all the hash value needed to perform an audit proof
    
    Argument:
    
    index: int
        The index of leaf with the target hash to check in the merkle tree
        
    Return:
    
    proof_index: list
        A list of the hash values of nodes that is needed to perform an
        audit proof for the target hash
    """
    def get_proof_index(self,index):
        
        """Error if the Merkle tree is not constructed, there is no leaf
        in the tree, the index is bigger than the number of leaves,
        or the index is a negative number"""
        if self.is_made == False or self.levels is None:
            raise ValueError("Merkle tree not built")
        elif index > len(self.leaves)-1 or index < 0:
            raise ValueError("Index invalid")
        
        """Initialize proof_index list to store the index require for audit proof
        at each level, and the hash value corresponding to the index"""
        proof_index = []
        
        
        no_levels = len(self.levels)
        level_count = 1
        
        """Current Proof Index: the index of the hash value used for 
        audit proof
        Current Node Index: the index of the node that the value belong 
        to at different level"""
        current_proof_index = 0
        current_node_index = index
        
        """Traversing up to all the levels of the Merkle tree"""
        while level_count < len(self.levels): 
            
            """If the current node is not a single node, we will find
            its sibling on the same level
            If not: we will skip this level and move on, because the
            corresponding node on the next level will have the same hash value"""
            if current_node_index != len(self.levels[no_levels-level_count])-1 or current_node_index%2 != 0:
                """If the node is on the right"""
                if current_node_index % 2 == 1:
                    current_proof_index = current_node_index - 1
                    current_proof_hash = self.levels[no_levels-level_count][current_proof_index]
                    proof_index.append(current_proof_hash)
                """If the node is on the left"""
                else:
                    current_proof_index = current_node_index + 1
                    current_proof_hash = self.levels[no_levels-level_count][current_proof_index]
                    proof_index.append(current_proof_hash)
            
            """Update the current node index to the index of the node in
            the upper level that contains the hash value we want to audit"""
            current_node_index = current_node_index/2
            level_count += 1
        
        return proof_index
    
    """
    Purpose: The actual audit proof, where we reverse engineer the merkle root
    based on the hash value we want to check, and the hash values of the 
    nodes required in this audit proof
    
    Argument:
    
    proof_index: list
        the list of hash values needed to perform an audit proof,
        based on the index of the hash value we want to check in the tree
    
    target_hash: str
        the hash value we want to check whether it is a valid member in the
        merkle tree
        
    merkle_root: str (default: None)
        the hash value of the merkle root we want to use to validate the
        membership of the target_hash
        
    Return:
    
    membership: boolean
        True if the target hash is a valid member of the merkle tree; False 
        if it is not a valid member of the merkle tree
    """
    def proof(self,proof_index,target_hash,merkle_root=None):
        if self.is_made is False:
            raise ValueError("Merkle tree not built")
        
        if merkle_root is None:
            merkle_root = self.get_merkle_root()
            
        """If there is no nodes needed for the proof, that menas the
        hash value we want to check should be at the root"""    
        if len(proof_index) == 0:
            return target_hash == merkle_root
        else:
            """Candidate Hash: a running storage for the intermediate hash
            values as we reverse engineer the merkle root level by level"""
            candidate_hash = target_hash
            for i in xrange(len(proof_index)):
                proof_hash = proof_index[i]
                """Rehash with the proof hash and candidate hash at each level"""
                candidate_hash = hashlib.sha256(hashlib.sha256(candidate_hash+proof_hash).digest()).digest()
                candidate_hash = candidate_hash.encode('hex')
        
        return candidate_hash == merkle_root