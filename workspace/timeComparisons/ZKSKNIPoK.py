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
nizk = stmt.prove({w: w.value})
finishProof = time.process_time_ns() - startProof

startVerify = time.process_time_ns()
v = stmt.verify(nizk)
finishVerify = time.process_time_ns() - startVerify

print("ZKSK-NIPoK Proof verified:", v)
print("ZKSK-NIPoK Proof Generation time:", finishProof)
print("ZKSK-NIPoK Proof Verification time:", finishVerify)