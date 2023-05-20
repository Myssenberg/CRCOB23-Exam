from petlib import ec
from zksk.utils.groups import make_generators

#modeled after "On Sigma Protocols" by Ivan Damgård page 9-10, first example in section 5
#names should match the naming in the paper.

#Generates a group over an elliptic curve(EC)
#Takes no arguments
#Returns group order, q, and group generator, g
def groupGen():
    #Generates an elliptic curve group.
    #p is not needed here when working with EC
    group = ec.EcGroup()
    q = group.order() #Order of the group
    g1, g2 = make_generators(2, group) #Group generator


    return group, q, g1, g2


#Generates secret and public key for Prover using the EC group
#Takes EC group order, q, and EC group generator, g, as arguments
#Returns Prover secret key(witness), w, and Prover public key, h.
def keygen(q, g1, g2):
    w = q.random() #secret key, prover witness
    h1 = w*g1 #EC public key
    h2 = w*g2
    return w, h1, h2


#Generates a Prover commitment (step one in protocol)
#Takes EC group order, q, and EC group generator, g, as arguments
#Returns Prover commitment, a, and Prover randomness, r.
def Prover_commitment(q, g1, g2):
    r = q.random() #Generates randomness for the commitment
    a1 = r*g1 #Computes the commitment
    a2 = r*g2
    return a1, a2 , r


#Generates a Verifier challenge (step two in protocol) randomly from the order of the group
#Takes EC group order, q, as argument
#Returns Verifier challenge, e.
def Verifier_challenge(q):
    e = q.random() #Computes random challenge to send to prover

    return e


#Generates Prover response (first part of step three in the protocol)
#Takes Prover randomness, r, challenge, e, prover witness, w, and EC order, q.
#Returns Prover response, z.
def Prover_response(r, e, w, q):
    z = r + e*w % q #Computes secret response
    return z


#Runs a full Proof of Knowledge
def proofGen(q, g1, g2, w):
    #Prover generates and "sends" commitment to Verifier.
    #Notice only Prover knows and keeps r
    commitment1, commitment2, r = Prover_commitment(q, g1, g2)

    #Verifier "receives" commitment. Generates challenge and "sends" it to Prover
    challenge = Verifier_challenge(q)

    #Prover "receives" challenge. Generates response and "sends" it to Verifier for verification
    response = Prover_response(r, challenge, w, q)

    return commitment1, commitment2, challenge, response

#Verifer Asserts if the ZKP is correct
#Takes EC group generator(g), response(z), commitment(a), Prover public key(h), challenge(e)
#Returns either True or False depending on whether the proof goes through.
def Verifier_verify(group, g1, g2, h1, h2, proof):
    a1, a2, e, z = proof
    
    v1 = z*g1 == a1+e*h1 #Verifies that the reponse corresponds with the commitment
    v2 = z*g2 == a2 + e * h2
    v_g1 = group.check_point(g1) #Checks that g is on the curve
    v_h1 = group.check_point(h1) #Checks that h is on the curve
    v_g2 = group.check_point(g2) #Checks that g is on the curve
    v_h2 = group.check_point(h2) #Checks that h is on the curve

    return v1 & v2 & v_g1 & v_g2 & v_h1 & v_h2



group, q, g1, g2 = groupGen() #Generates public knowledge
w, h1, h2 = keygen(q, g1, g2) #Prover generates their secret and public keys, "publishing" the public key
proof = proofGen(q, g1, g2, w)

#Verifier "receives" response. Verifies proof with:
#Public information: g, h
#Verifier generated information: challenge
#Information send by prover: commitment, response
verify = Verifier_verify(group, g1, g2, h1, h2, proof)
print("Proof verified:", verify)