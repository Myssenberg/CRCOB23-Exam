from petlib import ec, bn
from hashlib import sha256

#modeled after "On Sigma Protocols" by Ivan Damgård page 1, first example
#names should match the naming in the paper.

#Generates a group over an elliptic curve(EC)
#Takes no arguments
#Returns group, group order, q, and group generator, g
def groupGen():
    #Generates an elliptic curve group.
    #p is not needed here when working with EC
    group = ec.EcGroup()
    q = group.order() #Order of the group
    g = group.generator() #Group generator

    return group, q, g


#Generates secret and public key for Prover using the EC group
#Takes EC group order, q, and EC group generator, g, as arguments
#Returns Prover secret key(witness), w, and Prover public key, h.
def keygen(q, g):
    w = q.random() #secret key, prover witness
    h = w*g #EC public key
    return w, h


#Generates a Prover commitment (step one in protocol)
#Takes EC group order, q, and EC group generator, g, as arguments
#Returns Prover commitment, a, and Prover randomness, r.
def Prover_commitment(q, g):
    r = q.random() #Generates randomness for the commitment
    a = r*g #Computes the commitment
    return a, r


#Generates a Prover challenge (step two in protocol) with a hash function from the group generator, public key, and commitment
#Takes group generator, public key and commitment as arguments
#Returns Prover challenge, e.
def Prover_challenge(g, h, a):
    e = sha256(str(g+h+a).encode()).hexdigest()

    return e


#Generates Prover response (first part of step three in the protocol)
#Takes Prover randomness, r, challenge, e, prover witness, w, and EC order, q.
#Returns Prover response, z.
def Prover_response(r, e, w, q):
    z = r - bn.Bn.from_hex(e)*w % q #Computes secret response
    return z


#Runs a full Proof of Knowledge
def proofGen(q, g, w, h):
    #Prover generates commitment
    commitment, r = Prover_commitment(q, g)

    #Prover generates challenge
    challenge = Prover_challenge(g,h,commitment)

    #Prover generates response and "sends" commitment and response to Verifier for verification
    response = Prover_response(r, challenge, w, q)

    return commitment, response


#Verifer Asserts if the ZKP is correct
#Takes EC group generator(g), response(z), commitment(a), Prover public key(h), and group.
#Verifier generates challenge itself in the same way as prover has done, thus verifying the legitimacy
#Returns either True or False depending on whether the proof goes through.
def Verifier_verify(group, g, h, proof):
    a, z = proof

    e = sha256(str(g+h+a).encode()).hexdigest()

    v = a == z*g+bn.Bn.from_hex(e)*h #Verifies that the reponse corresponds with the commitment
    g_v = group.check_point(g) #Checks that g is on the curve
    g_h = group.check_point(h) #Checks that h is on the curve
    return v & g_v & g_h


group, q, g = groupGen() #Generates public knowledge
w, h = keygen(q, g) #Prover generates their secret and public keys, "publishing" the public key
proof = proofGen(q, g, w, h)

#Verifier "receives" response. Verifies proof with:
#Public information: g, h
#Verifier generated information: challenge (using the same hashfunction as prover)
#Information send by prover: commitment, response
v = Verifier_verify(group, g, h, proof)
print("Proof verified:", v)