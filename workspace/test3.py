from hashlib import sha256

def Prover_challenge(g, h, a):
    e = sha256(str(g+h+a).encode()).hexdigest()

    return e

prover = Prover_challenge(1, 2, 3)

verifier = sha256(str(1+2+3).encode()).hexdigest()

print("Prover:", prover)
print("Verifier:", verifier)
print("Identical:", prover==verifier)
