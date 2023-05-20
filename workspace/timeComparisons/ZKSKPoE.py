from petlib.ec import EcGroup
from zksk.utils.groups import make_generators
from zksk import Secret, DLRep
import time

group = EcGroup()

g1, g2 = make_generators(2, group)

order = group.order()

w = Secret(value=order.random())

h1 = w.value*g1
h2 = w.value*g2

stmt = DLRep(h1, w*g1) & DLRep(h2, w*g2)

startProof = time.process_time_ns()
prover = stmt.get_prover({w: w.value})
verifier = stmt.get_verifier()

commitment = prover.commit()
challenge = verifier.send_challenge(commitment)
response = prover.compute_response(challenge)
finishProof = time.process_time_ns() - startProof

startVerify = time.process_time_ns()
v = verifier.verify(response)
finishVerify = time.process_time_ns() - startVerify

print("ZKSK-PoE Proof verified:", v)
print("ZKSK-PoE Proof Generation time:", finishProof)
print("ZKSK-PoE Proof Verification time:", finishVerify)