from petlib.ec import EcGroup
from zksk.utils.groups import make_generators
from zksk import Secret, DLRep
import time


group = EcGroup()

g1, g2 = make_generators(2, group)

g = group.generator()

order = group.order()

startGen = time.process_time_ns()
w = Secret(value=order.random())

y1 = w.value*g1
h2 = w.value*g2

stmt = DLRep(y1, w*g1) # & DLRep(h2, w*g2)

nizk = stmt.prove({w: w.value})
finishGen = time.process_time_ns()-startGen

startVer = time.process_time_ns()
v = stmt.verify(nizk)
finishVer = time.process_time_ns() - startVer

print("Proof verified:", v)
print("Proof gen:", finishGen)
print("Proof ver:", finishVer)