from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass
from typing import Dict, List
import base64
import json
from BloomFilter import BloomFilter, ClusterHead
from bitarray import bitarray
from copy import deepcopy

"""
This is a very rudimentary scheme for group signature. Obviously in the real world it would be implemented in a way that would actually hide member ids and other
information below and would distribute keys in a better way. For the sake of time, sanity, and lack of collaborative efforts on the code, I've implemented it like this.
I would have liked to flesh this out more, having more realistics data isolation.
    - Kaleb Ashmore
"""

class GroupMember:
    def __init__(self, id):
        self.id = id
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def add_group(self, group):
        self.group_key = group.group_key
        self.group = group

    def sign_message(self, message: str):
        """Sign a message using member's key and group key"""
            
        # First sign with member's private key
        message_bytes = message.encode()
        
        member_signature = self.private_key.sign(
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
            'member_signature': base64.b64encode(member_signature).decode('utf-8'),
            'group_signature': base64.b64encode(group_signature).decode('utf-8')
        }

    def verify_signature(self, signature_data: dict):
        """Verify both member and group signatures"""

        member_signature = base64.b64decode(signature_data['member_signature'])
        group_signature = base64.b64decode(signature_data['group_signature'])

        try:
            if not self.group.check(signature_data=signature_data):
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

class GroupSignature:
    """
    Acts as the group object and the admin. Not realistic, but for proof of concept and simplicity I went with this.
    A lot of public variables that would, in real life, be private and encrypted.
    """
    def __init__(self):
        self.members: Dict[str, GroupMember] = {}
        self.group_key = self._generate_group_key()
        self.bloom1 = BloomFilter(500, 3)
        self.bloom_pub, self.priv = self.bloom1.generate_keys()
        self.cluster = ClusterHead(self.bloom_pub, self.priv)

        
    def _generate_group_key(self):
        """Generate the group's master private key"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    def add_member(self, member_id: str):
        """Add a new member to the group"""
        new_mem = GroupMember(id=member_id)
        new_mem.add_group(self)
        self.members[member_id] = new_mem

    def revoke_member(self, signature_data):
        message = signature_data['message'].encode()
        member_signature = base64.b64decode(signature_data['member_signature'])
        mem_id = None
        for member in self.members:
            try:
                self.members[member].public_key.verify(
                    member_signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                mem_id = self.members[member].id
                print(f"DEBUG: revoked {mem_id}")
            except Exception:
                continue

        if mem_id is None:
            print("Member is not part of the group")
            return False
        self.bloom1.add(mem_id)

    def check(self, signature_data):
        """Method 'pings' the group admin to check for membership and revocation status for privacy."""
        message = signature_data['message'].encode()
        member_signature = base64.b64decode(signature_data['member_signature'])
        mem_id = None
        for member in self.members:
            try:
                print(f"DEBUG: member check = {member}")
                self.members[member].public_key.verify(
                    member_signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                mem_id = self.members[member].id
                print(f"DEBUG: found {mem_id}")
                if mem_id is not None:
                    break
            except Exception:
                mem_id = None
                continue

        if mem_id is None:
            print("Member is not part of the group or message is mismatched to public key")
            return False

        # Verify that they are not a revoked user.
        if self.bloom1.check(mem_id):
            print(f"User \"{mem_id}\" is REVOKED")
            return False
        return True

def print_separator():
    print("\n" + "="*50 + "\n")

def main():
    # Create a new group
    group = GroupSignature()
    print("Group created successfully!")
    print_separator()

    size = 500  # Size of the Bloom filter
    hash_count = 3  # Number of hash functions
    bloom2 = BloomFilter(size, hash_count)

    chead_2_pub, chead2_priv = bloom2.generate_keys()
    cluster_2 = ClusterHead(chead_2_pub, chead2_priv) # Alluding to the comment up at the top, obviously this key exchange would need to be more secure IRL


    # Add multiple members
    members = ["Alice", "Bob", "verifier"] # Legitimate users
    for member in members:
        print(f"Adding member: {member}")
        group.add_member(member)
    print("\nAll members added successfully!")
    print(str(group.members))

    verifier = group.members['verifier'] # For testing purposes, the member list is public.

    ### Demonstrate message signing by different members
    messages = {
        "Alice": "Hello everyone! This is Alice.",
        "Bob": "Important project update: Meeting at 2 PM.",
        "Charlie": "Confirming receipt of the documents."
    }

    # Store signatures for later verification
    signatures = {}

    # Non-member for membership checking
    print_separator()
    print("Demonstrating message signing by each member:\n")
    print(f"Non-Member Charlie Signing. Expected Message: {messages['Charlie']}")
    print("Signature details:")
    charlie = GroupMember("Charlie") # False member
    charlie.add_group(group)
    c_signature = charlie.sign_message(messages["Charlie"])
    signatures['Charlie'] = c_signature
    print(f"- Message: {c_signature['message']}")
    print(f"- Member Signature (truncated): {c_signature['member_signature'][:30]}...")
    print(f"- Group Signature (truncated): {c_signature['group_signature'][:30]}...")

    for member, message in messages.items():
        if member is "Charlie":
                continue # Skip charlie since he is not in the member list
        print(f"\n{member} Signing. Expected Message: '{message}'")
        try:
            signature = group.members[member].sign_message(message)
            signatures[member] = signature
            print("Signature details:")
            # print(f"- Member ID: {signature['member_id']}")
            print(f"- Message: {signature['message']}")
            print(f"- Member Signature (truncated): {signature['member_signature'][:30]}...")
            print(f"- Group Signature (truncated): {signature['group_signature'][:30]}...")
        except Exception as e:
            print(f"Error signing message: {str(e)}")

    print_separator()

    ### Demonstrate signature verification
    print("Verifying all signatures:") 

    for member, signature in signatures.items():
        print(f"\nVerifying {member}'s message:")
        is_valid = verifier.verify_signature(signature)
        print(f"Message: '{signature['message']}'")
        print(f"Verification result: {'Valid' if is_valid else 'Invalid'}")
        print()

    print_separator()

    ### Demonstrate new messages are valid
    print("Testing if new messages are properly validated\n")
    print(f"Bob is Signing. Expected Message: Something else important")
    new_signature_bob = group.members["Bob"].sign_message("Something else important")
    print("Signature details:")
    print(f"- Message: {new_signature_bob['message']}")
    print(f"- Member Signature (truncated): {new_signature_bob['member_signature'][:30]}...")
    print(f"- Group Signature (truncated): {new_signature_bob['group_signature'][:30]}...")

    is_valid = verifier.verify_signature(new_signature_bob)
    print(f"Verification result: {'Valid' if is_valid else 'Invalid'}")
    print()
    print_separator()

    ### Demonstrate tampering detection
    print("Demonstrating tampering detection:")
    
    # Create a tampered signature by modifying the message
    tampered_signature = deepcopy(signatures["Alice"])
    tampered_signature["message"] = "Tampered message: Send $1000 to account XYZ"
    
    print("\nOriginal Message:", signatures["Alice"]["message"])
    print("Tampered Message:", tampered_signature["message"])
    
    print("\nVerifying original signature:", 
          "Valid" if verifier.verify_signature(signatures["Alice"]) else "Invalid")
    print("Verifying tampered signature:", 
          "Valid" if verifier.verify_signature(tampered_signature) else "Invalid")

    print_separator()

    ### Demonstrate Bloom Filter Revocation
    # Cluster 1 revokes member
    print("Revoking Alice and adding to bloom filter")
    revoked_members = ["Alice"]
    for member in revoked_members:
        group.revoke_member(signature_data=signatures["Alice"])
   
    # Cluster 1 signs the updated Bloom filter
    signature, message = group.cluster.sign_bloom_filter(group.bloom1)

    # Cluster 2 receives and verifies the update
    is_verified = cluster_2.verify_bloom_filter(signature, message, group.cluster)
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

    print("\nVerifying all signatures post revocation:")
    for member, signature in signatures.items():
        print(f"\nVerifying {member}'s message:")
        is_valid = verifier.verify_signature(signature)
        print(f"Message: '{signature['message']}'")
        print(f"Verification result: {'Valid' if is_valid else 'Invalid'}")

    print("\nRevoking Bob and adding to bloom filter")
    bloom2.add("Bob") # overly simple implementation compared to the other method, but gets the point across.
    signature, message = cluster_2.sign_bloom_filter(bloom2)
    is_verified = group.cluster.verify_bloom_filter(signature=signature, message=message, cluster=cluster_2)
    if is_verified:
        print("Cluster 1: Verified Cluster 2's Bloom Filter")
        received_bloom = BloomFilter(size, hash_count)
        received_bloom.bit_array = bitarray()
        received_bloom.bit_array.frombytes(message)
        received_bloom.bit_array = received_bloom.bit_array[:size]

        group.bloom1.merge(received_bloom)
        print("Cluster 1: Bloom filter updated")
    else:
        print("Cluster 1: Verification failed")

    print("Verifying all signatures post revocation:")
    for member, signature in signatures.items():
        print(f"\nVerifying {member}'s message:")
        is_valid = verifier.verify_signature(signature)
        print(f"Message: '{signature['message']}'")
        print(f"Verification result: {'Valid' if is_valid else 'Invalid'}")
    
    ### Test if new messages are properly revoked
    print_separator()
    print("Demonstrating that new messages from Alice are revoked")
    new_signature = group.members["Alice"].sign_message("new message blah blah")
    print("Signature details:")
    print(f"- Message: {new_signature['message']}")
    print(f"- Member Signature (truncated): {new_signature['member_signature'][:30]}...")
    print(f"- Group Signature (truncated): {new_signature['group_signature'][:30]}...")

    is_valid = verifier.verify_signature(new_signature)
    print(f"Message: '{new_signature['message']}'")
    print(f"Verification result: {'Valid' if is_valid else 'Invalid'}")
    print()

if __name__ == "__main__":
    main()