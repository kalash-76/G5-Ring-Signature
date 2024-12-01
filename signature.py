from bitarray import bitarray
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import random
 
# -------------------------------
# BLOOM FILTER IMPLEMENTATION
# -------------------------------
 
class BloomFilter:
    def __init__(self, size, hash_count):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bitarray(size)
        self.bit_array.setall(0)
   
    def add(self, item):
        for i in range(self.hash_count):
            index = self._hash(item, i) % self.size
            self.bit_array[index] = 1
   
    def check(self, item):
        for i in range(self.hash_count):
            index = self._hash(item, i) % self.size
            if not self.bit_array[index]:
                return False
        return True
   
    def _hash(self, item, i):
        return int(sha256((item + str(i)).encode()).hexdigest(), 16)
 
    def merge(self, other_bloom):
        """Merge another Bloom filter with this one using bitwise OR."""
        self.bit_array |= other_bloom.bit_array
 
# -------------------------------
# GROUP SIGNATURE IMPLEMENTATION
# -------------------------------
 
class ClusterHead:
    def __init__(self, group_public_key, private_key):
        self.group_public_key = group_public_key
        self.private_key = private_key
   
    def sign_bloom_filter(self, bloom_filter):
        message = bloom_filter.bit_array.tobytes()
        hash_message = SHA256.new(message)
        signature = pkcs1_15.new(self.private_key).sign(hash_message)
        return signature, message
   
    def verify_bloom_filter(self, signature, message):
        hash_message = SHA256.new(message)
        try:
            pkcs1_15.new(self.group_public_key).verify(hash_message, signature)
            return True
        except (ValueError, TypeError):
            return False
 
# -------------------------------
# DEMO SCENARIO
# -------------------------------
 
# Generate RSA keys for demonstration
def generate_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return public_key, private_key
 
# Simulate cluster heads
def demo_scenario():
    # Generate group keys
    group_public_key, cluster1_private_key = generate_keys()
    _, cluster2_private_key = generate_keys()
 
    # Initialize cluster heads
    cluster1 = ClusterHead(group_public_key, cluster1_private_key)
    cluster2 = ClusterHead(group_public_key, cluster2_private_key)
 
    # Initialize Bloom Filters
    size = 500  # Size of the Bloom filter
    hash_count = 3  # Number of hash functions
    bloom1 = BloomFilter(size, hash_count)
    bloom2 = BloomFilter(size, hash_count)
 
    # Cluster 1 revokes members
    revoked_members = ["user1", "user2"]
    for member in revoked_members:
        bloom1.add(member)
   
    # Cluster 1 signs the updated Bloom filter
    signature, message = cluster1.sign_bloom_filter(bloom1)
 
    # Cluster 2 receives and verifies the update
    is_verified = cluster2.verify_bloom_filter(signature, message)
    if is_verified:
        print("Cluster 2: Verified Cluster 1's Bloom filter")
        # Convert message back to Bloom filter
        received_bloom = BloomFilter(size, hash_count)
        received_bloom.bit_array = bitarray()
        received_bloom.bit_array.frombytes(message)
        received_bloom.bit_array = received_bloom.bit_array[:size]  # Ensure the bit_array matches the expected size
 
        # Merge with local Bloom filter
        bloom2.merge(received_bloom)
        print("Cluster 2: Bloom filter updated")
    else:
        print("Cluster 2: Verification failed")
 
    # Check membership in Cluster 2's Bloom filter
    test_members = ["user1", "user3"]
    for member in test_members:
        print(f"Is {member} revoked? {'Yes' if bloom2.check(member) else 'No'}")
 
# Run the demo
if __name__ == "__main__":
    demo_scenario()