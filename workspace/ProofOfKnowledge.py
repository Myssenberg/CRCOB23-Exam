from petlib import ec

def groupGen():
    group = ec.EcGroup()
    order = group.order()
    g = group.generator()

    return (group, order, g)

def keygen(order, g):
    w = order.random() #secret key
    h = w*g #elliptic curve public key
    return w, h

def Pcommitment(order, g, w):
    r = order.random()
    com = r*g
    return com, r

def Vchallenge(order, g):
    c = order.random()

    return c

def Presponse(r, c, w):
    z = r + c*w
    return z

def Vverify(g, z, com, h, c):
    v = z*g == com+c*h
    return v

def proof():
    group, order, g = groupGen()
    w, h = keygen(order, g)

    commitment, r = Pcommitment(order, g, w)

    challenge = Vchallenge(order, g)

    response = Presponse(r, challenge, w)

    verify = Vverify(g, response, commitment, h, challenge)

    print("Proof verified:", verify)

proof()