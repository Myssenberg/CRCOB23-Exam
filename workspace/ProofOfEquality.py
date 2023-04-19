from petlib import ec

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
    g = group.generator() #Group generator

    return group, q, g


#Generates secret and public key for Prover using the EC group
#Takes EC group order, q, and EC group generator, g, as arguments
#Returns Prover secret key(witness), w, and Prover public key, h.
def keygen(q, g, g_):
    w = q.random() #secret key, prover witness
    h = w*g #EC public key
    h_ = w*g_
    return w, h, h_


#Generates a Prover commitment (step one in protocol)
#Takes EC group order, q, and EC group generator, g, as arguments
#Returns Prover commitment, a, and Prover randomness, r.
def Prover_commitment(q, g, g_):
    r = q.random() #Generates randomness for the commitment
    a = r*g #Computes the commitment
    a_ = r*g_
    return a, a_ , r


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


#Verifer Asserts if the ZKP is correct
#Takes EC group generator(g), response(z), commitment(a), Prover public key(h), challenge(e)
#Returns either True or False depending on whether the proof goes through.
def Verifier_verify(g, g_, z, a, a_ , h, h_ , e, group):
    v = z*g == a+e*h #Verifies that the reponse corresponds with the commitment
    v_ = z*g_ == a_ + e * h_
    v_g = group.check_point(g) #Checks that g is on the curve
    v_h = group.check_point(h) #Checks that h is on the curve
    v_g_ = group.check_point(g_) #Checks that g is on the curve
    v_h_ = group.check_point(h_) #Checks that h is on the curve

    return v & v_g & v_g_ & v_h & v_h_


#Runs a full Proof of Knowledge
def proof():
    group, q, g = groupGen() #Generates public knowledge
    w, h, h_ = keygen(q, g, g_) #Prover generates their secret and public keys, "publishing" the public key

    #Prover generates and "sends" commitment to Verifier.
    #Notice only Prover knows and keeps r
    commitment, r = Prover_commitment(q, g)

    #Verifier "receives" commitment. Generates challenge and "sends" it to Prover
    challenge = Verifier_challenge(q)

    #Prover "receives" challenge. Generates response and "sends" it to Verifier for verification
    response = Prover_response(r, challenge, w, q)

    #Verifier "receives" response. Verifies proof with:
    #Public information: g, h
    #Verifier generated information: challenge
    #Information send by prover: commitment, response
    verify = Verifier_verify(g, response, commitment, h, challenge, group)

    print("Proof verified:", verify)

proof()