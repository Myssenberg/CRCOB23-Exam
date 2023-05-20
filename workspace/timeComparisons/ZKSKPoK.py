from petlib.ec import EcGroup
from zksk import Secret, DLRep
import time

group = EcGroup()

g = group.generator()

order = group.order()

w = Secret(value=order.random())

h = w.value*g

stmt = DLRep(h, w*g)

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

print("ZKSK-PoK Proof verified:", v)
print("ZKSK-PoK Proof Generation time:", finishProof)
print("ZKSK-PoK Proof Verification time:", finishVerify)