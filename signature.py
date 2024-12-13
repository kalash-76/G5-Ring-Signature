from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass
from typing import Dict, List
import base64
import json
from BloomFilter import BloomFilter, ClusterHead
from bitarray import bitarray


@dataclass
class GroupMember:
    id: str
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey

class GroupSignature:
    def __init__(self, group_name: str):
        self.group_name = group_name
        self.members: Dict[str, GroupMember] = {}
        self.group_key = self._generate_group_key()
        self.bloom1 = BloomFilter(500, 3)
        self.bloom_pub, priv = self.bloom1.generate_keys()
        self.cluster = ClusterHead(self.bloom_pub, priv)

        
    def _generate_group_key(self) -> rsa.RSAPrivateKey:
        """Generate the group's master private key"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    def add_member(self, member_id: str) -> None:
        """Add a new member to the group"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        self.members[member_id] = GroupMember(
            id=member_id,
            private_key=private_key,
            public_key=public_key
        )
    
    def sign_message(self, member_id: str, message: str) -> dict:
        """Sign a message using member's key and group key"""
        if member_id not in self.members:
            raise ValueError(f"Member {member_id} not found in group")
            
        # First sign with member's key
        member = self.members[member_id]
        message_bytes = message.encode()
        
        member_signature = member.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Then sign with group key
        group_signature = self.group_key.sign(
            member_signature,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return {
            'message': message,
            'member_id': member_id,
            'member_signature': base64.b64encode(member_signature).decode('utf-8'),
            'group_signature': base64.b64encode(group_signature).decode('utf-8')
        }
    
    def verify_signature(self, signature_data: dict) -> bool:
        """Verify both member and group signatures"""
        try:
            member_id = signature_data['member_id']
            message = signature_data['message'].encode()
            member_signature = base64.b64decode(signature_data['member_signature'])
            group_signature = base64.b64decode(signature_data['group_signature'])
            
            if member_id not in self.members:
                return False

            # Verify that they are not revoked users.
            if self.bloom1.check(member_id):
                print("User is REVOKED")
                return False
                
            member = self.members[member_id]
            
            # Verify member's signature
            try:
                member.public_key.verify(
                    member_signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception:
                return False
            
            # Verify group signature
            try:
                self.group_key.public_key().verify(
                    group_signature,
                    member_signature,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception:
                return False
                
            return True
            
        except (KeyError, ValueError):
            return False

    def export_member_key(self, member_id: str) -> str:
        """Export a member's private key in PEM format"""
        if member_id not in self.members:
            raise ValueError(f"Member {member_id} not found in group")
            
        private_key = self.members[member_id].private_key
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem.decode('utf-8')

def print_separator():
    print("\n" + "="*50 + "\n")

def main():
    # Create a new group
    print("Creating new group 'CryptoTeam'...")
    group = GroupSignature("CryptoTeam")
    print("Group created successfully!")
    print_separator()

    # Bloom Filter 
    # chead1_key = rsa.generate_private_key(
    #         public_exponent=65537,
    #         key_size=2048
    #     )
    size = 500  # Size of the Bloom filter
    hash_count = 3  # Number of hash functions
    bloom2 = BloomFilter(size, hash_count)

    _, chead2_priv = bloom2.generate_keys()
    cluster_2 = ClusterHead(group.bloom_pub, chead2_priv)


    # Add multiple members
    members = ["Alice", "Bob", "Charlie"]
    for member in members:
        if member is not "Charlie": # False member for testing 
            print(f"Adding member: {member}")
            group.add_member(member)
    print("\nAll members added successfully!")

    # Demonstrate message signing by different members
    messages = {
        "Alice": "Hello everyone! This is Alice.",
        "Bob": "Important project update: Meeting at 2 PM.",
        "Charlie": "Confirming receipt of the documents."
    }

    # Store signatures for later verification
    signatures = {}

    print("Demonstrating message signing by each member:")
    for member, message in messages.items():
        print(f"\n{member}'s Message: '{message}'")
        try:
            signature = group.sign_message(member, message)
            signatures[member] = signature
            print(f"Signature created successfully")
            print("Signature details:")
            print(f"- Member ID: {signature['member_id']}")
            print(f"- Message: {signature['message']}")
            print(f"- Member Signature (truncated): {signature['member_signature'][:30]}...")
            print(f"- Group Signature (truncated): {signature['group_signature'][:30]}...")
        except Exception as e:
            print(f"Error signing message: {str(e)}")

    print_separator()

    # Demonstrate signature verification
    print("Verifying all signatures:")
    for member, signature in signatures.items():
        is_valid = group.verify_signature(signature)
        print(f"\nVerifying {member}'s message:")
        print(f"Message: '{signature['message']}'")
        print(f"Verification result: {'Valid' if is_valid else 'Invalid'}")

    print_separator()

    # Demonstrate tampering detection
    print("Demonstrating tampering detection:")
    
    # Create a tampered signature by modifying the message
    tampered_signature = signatures["Alice"].copy()
    tampered_signature["message"] = "Tampered message: Send $1000 to account XYZ"
    
    print("\nOriginal Message:", signatures["Alice"]["message"])
    print("Tampered Message:", tampered_signature["message"])
    
    print("\nVerifying original signature:", 
          "Valid" if group.verify_signature(signatures["Alice"]) else "Invalid")
    print("Verifying tampered signature:", 
          "Valid" if group.verify_signature(tampered_signature) else "Invalid")

    print_separator()

    #### Demonstrate Bloom Filter Revocation
    # Cluster 1 revokes members
    revoked_members = ["Alice"]
    for member in revoked_members:
        group.bloom1.add(member)
   
    # Cluster 1 signs the updated Bloom filter
    signature, message = group.cluster.sign_bloom_filter(group.bloom1)

    # Cluster 2 receives and verifies the update
    is_verified = cluster_2.verify_bloom_filter(signature, message)
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

    print("Verifying all signatures post revocation:")
    for member, signature in signatures.items():
        is_valid = group.verify_signature(signature)
        print(f"\nVerifying {member}'s message:")
        print(f"Message: '{signature['message']}'")
        print(f"Verification result: {'Valid' if is_valid else 'Invalid'}")

if __name__ == "__main__":
    main()