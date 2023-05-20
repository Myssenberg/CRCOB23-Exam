import unittest
import ProofOfKnowledge as PoK
import NIProofOfKnowledge as NIPoK
import ProofOfEquality as PoE
import NIProofOfEquality as NIPoE

class TestPoK(unittest.TestCase):
    def test_proof_correct_values(self):
        group, q, g = PoK.groupGen()
        w, h = PoK.keygen(q, g)
        proof = PoK.proofGen(q, g, w)

        self.assertTrue(PoK.Verifier_verify(group, g, h, proof))
    
    def test_proof_wrong_witness(self):
        group, q, g = PoK.groupGen()
        w, h = PoK.keygen(q, g)
        proof = PoK.proofGen(q, g, 0)

        self.assertFalse(PoK.Verifier_verify(group, g, h, proof))
    
    def test_proof_wrong_public_key(self):
        group, q, g = PoK.groupGen()
        w, h = PoK.keygen(q, g)
        proof = PoK.proofGen(q, g, w)

        self.assertFalse(PoK.Verifier_verify(group, g, 2*g, proof))

class TestNIPoK(unittest.TestCase):
    def test_proof_correct_values(self):
        group, q, g = NIPoK.groupGen()
        w, h = NIPoK.keygen(q, g)
        proof = NIPoK.proofGen(q, g, w, h)

        self.assertTrue(NIPoK.Verifier_verify(group, g, h, proof))
    
    def test_proof_wrong_witness(self):
        group, q, g = NIPoK.groupGen()
        w, h = NIPoK.keygen(q, g)
        proof = NIPoK.proofGen(q, g, 0, h)

        self.assertFalse(NIPoK.Verifier_verify(group, g, h, proof))
    
    def test_proof_wrong_public_key(self):
        group, q, g = NIPoK.groupGen()
        w, h = NIPoK.keygen(q, g)
        proof = NIPoK.proofGen(q, g, w, 2*g)

        self.assertFalse(NIPoK.Verifier_verify(group, g, h, proof))

class TestPoE(unittest.TestCase):
    def test_proof_correct_values(self):
        group, q, g1, g2 = PoE.groupGen()
        w, h1, h2 = PoE.keygen(q, g1, g2)
        proof = PoE.proofGen(q, g1, g2, w)

        self.assertTrue(PoE.Verifier_verify(group, g1, g2, h1, h2, proof))
    
    def test_proof_wrong_witness(self):
        group, q, g1, g2 = PoE.groupGen()
        w, h1, h2 = PoE.keygen(q, g1, g2)
        proof = PoE.proofGen(q, g1, g2, 0)

        self.assertFalse(PoE.Verifier_verify(group, g1, g2, h1, h2, proof))
    
    def test_proof_wrong_public_key(self):
        group, q, g1, g2 = PoE.groupGen()
        w, h1, h2 = PoE.keygen(q, g1, g2)
        proof = PoE.proofGen(q, g1, g2, w)

        self.assertFalse(PoE.Verifier_verify(group, g1, g2, 2*g1, h2, proof))
    
    def test_proof_switched_public_keys(self):
        group, q, g1, g2 = PoE.groupGen()
        w, h1, h2 = PoE.keygen(q, g1, g2)
        proof = PoE.proofGen(q, g1, g2, w)

        self.assertFalse(PoE.Verifier_verify(group, g1, g2, h2, h1, proof))

class TestNIPoE(unittest.TestCase):
    def test_proof_correct_values(self):
        group, q, g1, g2 = NIPoE.groupGen()
        w, h1, h2 = NIPoE.keygen(q, g1, g2)
        proof = NIPoE.proofGen(q, g1, g2, h1, h2, w)

        self.assertTrue(NIPoE.Verifier_verify(group, g1, g2, h1, h2, proof))
    
    def test_proof_wrong_witness(self):
        group, q, g1, g2 = NIPoE.groupGen()
        w, h1, h2 = NIPoE.keygen(q, g1, g2)
        proof = NIPoE.proofGen(q, g1, g2, h1, h2, 0)

        self.assertFalse(NIPoE.Verifier_verify(group, g1, g2, h1, h2, proof))
    
    def test_proof_wrong_public_key(self):
        group, q, g1, g2 = NIPoE.groupGen()
        w, h1, h2 = NIPoE.keygen(q, g1, g2)
        proof = NIPoE.proofGen(q, g1, g2, h1, h2, w)

        self.assertFalse(NIPoE.Verifier_verify(group, g1, g2, 2*g1, h2, proof))
    
    def test_proof_switched_public_keys(self):
        group, q, g1, g2 = NIPoE.groupGen()
        w, h1, h2 = NIPoE.keygen(q, g1, g2)
        proof = NIPoE.proofGen(q, g1, g2, h1, h2, w)

        self.assertFalse(NIPoE.Verifier_verify(group, g1, g2, h2, h1, proof))
     

if __name__=='__main__':
	unittest.main()