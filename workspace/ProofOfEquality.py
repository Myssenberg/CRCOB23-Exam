"""Elliptic curve proof of equality

This file contains an elliptic curve implementation of
the proof of equality described on page 9-10, first example in section 5,
in Ivan Damgård's paper "On Sigma-Protocols".

This file consists of functions that together can be used to run
a full proof of equality.

This file requires that the environment you are running on have the "petlib" and "ZKSK"
libraries installed.

The file contains the following functions:
    - groupGen: returns the EC group, group order, and two group generators
    - keyGen: returns the key set consisting of a secret and two public keys
    - Prover_commitment: returns the two commitments and prover randomness
    - Verifier_challenge: returns the challenge
    - Prover_response: returns the response
    - proofGen: returns the generated proof consisting of
                commitment, challenge, response
    - verify: returns True or False depending on whether the
              proof was accepted

At the end of the file some examples of how to run a full proof of equality
as well as how the time taking is done for the analysis of the project.
These are commented out, but are kept in the file for documentation purposes.
"""

from petlib import ec
from zksk.utils.groups import make_generators

def groupGen():
    """Generates an EC group, group order and generator

    No args

    Returns:
        group (EcGroup): the EC group from an EC over a finite field
        q (Bn): the group order
        g1, g2 (EcPt): two group generators
    """

    group = ec.EcGroup()
    q = group.order()

    #using the "zksk" library method for getting two different
    #generators for the same EC group
    g1, g2 = make_generators(2, group)

    return group, q, g1, g2

def keygen(q, g1, g2):
    """Generates a secret and two public keys for Prover using the EC group

    Args:
        q (Bn): the group order
        g1, g2 (EcPt): the two group generators

    Returns:
        w (Bn): the Prover secret key, also called the witness
        h1, h2 (EcPt): the two Prover public keys
    """

    w = q.random()
    h1 = w*g1
    h2 = w*g2
    
    return w, h1, h2

def Prover_commitment(q, g1, g2):
    """Generates a two Prover commitments (step one in protocol)

    Args:
        q (Bn): the group order
        g1, g2 (EcPt): the two group generators

    Returns:
        a1, a2 (EcPt): the two Prover commitments to randomness r
        r (Bn): randomness
        
    """
    
    r = q.random()
    a1 = r*g1
    a2 = r*g2
    
    return a1, a2, r

def Verifier_challenge(q):
    """Generates a Verifier challenge (step two in protocol)

    Args:
        q (Bn): the group order

    Returns:
        e (Bn): random challenge
        
    """

    e = q.random()

    return e

def Prover_response(r, e, w, q):
    """Generates a Prover response (step three in protocol)

    Args:
        r (Bn): randomness
        e (Bn): random challenge from verifier
        w (Bn): the Prover witness
        q (Bn): the group order

    Returns:
        z (Bn): the Prover response
        
    """

    z = r + e*w % q
    
    return z

def proofGen(q, g1, g2, w):
    """Generates the full proof
    commitment, challenge and response

    Args:
        q (Bn): the group order
        g1, g2 (EcPt): the two group generators
        w (Bn): the Prover witness
        

    Returns:
        a1, a1 (EcPt): the two Prover commitments to randomness r
        e (Bn): random challenge from verifier
        z (Bn): the Prover response 
    """

    #Prover generates and "sends" commitments to Verifier.
    #Notice only Prover knows and keeps r
    commitment1, commitment2, r = Prover_commitment(q, g1, g2)

    #Verifier "receives" commitment. Generates challenge and "sends" it to Prover
    challenge = Verifier_challenge(q)

    #Prover 'receives' challenge. Generates response.
    response = Prover_response(r, challenge, w, q)

    #Prover 'sends' proof to Verifier for verification
    return commitment1, commitment2, challenge, response

def verify(group, g1, g2, h1, h2, proof):
    """Verifies the full proof received from the prover

    Args:
        group (EcGroup): the EC group from an EC over a finite field
        g1, g2 (EcPt): the two group generators
        h1, h2 (EcPt): the two Prover public keys
        proof (EcPt, EcPt, Bn, Bn): commitment1, commitment2, challenge and response
        
    Returns:
        (bool) : returns true only if all checks are accepted, else false 
    """
    
    a1, a2, e, z = proof
    
    #Verifies that the reponse corresponds with the commitments
    v1 = z*g1 == a1+e*h1 
    v2 = z*g2 == a2 + e * h2

    #Checks that the generators and public keys are on the curve
    v_g1 = group.check_point(g1)
    v_h1 = group.check_point(h1)
    v_g2 = group.check_point(g2)
    v_h2 = group.check_point(h2)

    #All checks should be True for the proof to be accepted
    return v1 & v2 & v_g1 & v_g2 & v_h1 & v_h2

#Generation of public knowledge
group, q, g1, g2 = groupGen()

#Prover generates their secret and public keys, "publishing" the public keys
w, h1, h2 = keygen(q, g1, g2)

#Prover generates proof, with challenge from Verifier
proof = proofGen(q, g1, g2, w)

#Verifier "receives" proof and verifies it:
v = verify(group, g1, g2, h1, h2, proof)

print("Proof verified:", v)
