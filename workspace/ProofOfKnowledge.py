"""Elliptic curve proof of knowledge

This file contains an elliptic curve implementation of
the proof of knowledge described on page 1, first example,
in Ivan Damgård's paper "On Sigma-Protocols".

This file consists of functions that together can be used to run
a full proof of knowledge.

This file requires that the environment you are running on have the "petlib"
library installed.

The file contains the following functions:
    - groupGen: returns the EC group, group order, and group generator
    - keyGen: returns the key pair consisting of secret and public key
    - Prover_commitment: returns the commitment and prover randomness
    - Verifier_challenge: returns the challenge
    - Prover_response: returns the response
    - proofGen: returns the generated proof consisting of
                commitment, challenge, response
    - verify: returns True or False depending on whether the
              proof was accepted

At the end of the file some examples of how to run a full proof of knowledge
as well as how the time taking is done for the analysis of the project.
These are commented out, but are kept in the file for documentation purposes.
"""

from petlib import ec

def groupGen():
    """Generates an EC group, group order and generator

    No args

    Returns:
        group (EcGroup): the EC group from an EC over a finite field
        q (Bn): the group order
        g (EcPt): the group generator
    """

    group = ec.EcGroup()
    q = group.order()
    g = group.generator()

    return group, q, g

def keyGen(q, g):
    """Generates a secret and public key for Prover using the EC group

    Args:
        q (Bn): the group order
        g (EcPt): the group generator

    Returns:
        w (Bn): the Prover secret key, also called the witness
        h (EcPt): the Prover public key
    """

    w = q.random()
    h = w*g
    
    return w, h

def Prover_commitment(q, g):
    """Generates a Prover commitment (step one in protocol)

    Args:
        q (Bn): the group order
        g (EcPt): the group generator

    Returns:
        a (EcPt): the Prover commitment to randomness r
        r (Bn): randomness
        
    """

    r = q.random()
    a = r*g

    return a, r

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

def proofGen(q, g, w):
    """Generates the full proof
    commitment, challenge and response

    Args:
        q (Bn): the group order
        g (EcPt): the group generator
        w (Bn): the Prover witness
        

    Returns:
        a (EcPt): the Prover commitment to randomness r
        e (Bn): random challenge from verifier
        z (Bn): the Prover response 
    """

    #Prover generates and 'sends' commitment to Verifier.
    #Notice only Prover knows and keeps r
    commitment, r = Prover_commitment(q, g)

    #Verifier 'receives' commitment. Generates challenge and 'sends' it to Prover
    challenge = Verifier_challenge(q)

    #Prover 'receives' challenge. Generates response.
    response = Prover_response(r, challenge, w, q)

    #Prover 'sends' proof to Verifier for verification
    return commitment, challenge, response

def verify(group, g, h, proof):
    """Verifies the full proof received from the prover

    Args:
        group (EcGroup): the EC group from an EC over a finite field
        g (EcPt): the group generator
        h (EcPt): the Prover public key
        proof (EcPt, Bn, Bn): commitment, challenge and response
        
    Returns:
        (bool) : returns true only if all checks are accepted, else false 
    """

    a, e, z = proof

    #Verifies that the reponse corresponds with the commitment
    v = z*g == a+e*h

    #Checks that g and h are on the curve
    g_v = group.check_point(g) 
    h_v = group.check_point(h)

    #All checks should be True for the proof to be accepted
    return v & g_v & h_v


#Generation of public knowledge
group, q, g = groupGen()

#Prover generates their secret and public key, "publishing" the public key
w, h = keyGen(q, g)

#Prover generates proof, with challenge from Verifier
proof = proofGen(q, g, w)

#Verifier "receives" proof and verifies it:
v = verify(group, g, h, proof)

print("Proof verified:", v)