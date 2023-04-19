from hashlib import sha256
from petlib.ec import EcGroup, EcPt

# Create an elliptic curve group
group = EcGroup()

# Get the group order
order = group.order()

g = group.generator()

# Hash a random string to a point on the curve
random_string = b"some random string"
h = int.from_bytes(sha256(random_string).digest(), "big")
new_point = EcPt.from_binary(bytes(h*g))

# Multiply the new point by the group order to obtain a new generator
new_generator = group.multiply(new_point, order)


print("Old generator:", g)
print("New generator:", new_generator)