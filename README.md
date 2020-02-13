# Verifiable Random Function (VRF)

A simple and self-contained Python 3 reference implementation of the
[draft-irtf-cfrg-vrf-06](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06)
specification corresponding to the ECVRF-EDWARDS25519-SHA512-Elligator2 
ciphersuite configuration. This code is suitable for demonstration, 
exploration and the generation of test vectors to aid porting.
Significant portions  of the lower-level ed25519-related operations 
were directly adapted from those provided in [Bernstein's](https://ed25519.cr.yp.to/) 
sample [ed25519.py](https://ed25519.cr.yp.to/python/ed25519.py) code.

> **Please note:** *This code is alpha-quality and not suitable for production.
> While a limited testing infrastructure is provided, the code may be incomplete,
> inefficient, incorrect and/or insecure.*

The `ecvrf_edwards25519_sha512_elligator2.py` file retains a
significant amount of documentation extracted from the specification
to aid in understanding, and provides a simple API as follows:

~~~python
# Section 5.1. ECVRF Proving
def ecvrf_prove(sk, alpha_string):
    """
    Input:
        sk - VRF private key
        alpha_string - input alpha, an octet string
    Output:
        pi_string - VRF proof, octet string of length ptLen+n+qLen
    """
...


# Section 5.2. ECVRF Proof To Hash
def ecvrf_proof_to_hash(pi_string):
    """
    Input:
        pi_string - VRF proof, octet string of length ptLen+n+qLen
    Output:
        "INVALID", or beta_string - VRF hash output, octet string of length hLen
    Important note:
        ECVRF_proof_to_hash should be run only on pi_string that is known to have been
        produced by ECVRF_prove, or from within ECVRF_verify as specified in Section 5.3.
    """
...


# Section 5.3. ECVRF Verifying
def ecvrf_verify(y, pi_string, alpha_string):
    """
    Input:
        y - public key, an EC point
        pi_string - VRF proof, octet string of length ptLen+n+qLen
        alpha_string - VRF input, octet string
    Output:
        ("VALID", beta_string), where beta_string is the VRF hash output, octet string
        of length hLen; or "INVALID"
    """
...
~~~

The code is sensitized to the presence of a `test_dict` in the `globals()` space.
If present, the code asserts against values in the dict as well as samples those
same values. This allows for checking intermediate calculations as well as generating
test vectors to aid in porting. If the `test_dict` is not present, the code runs
unhindered. Examples of this are in the testing file.

All testcases are in `ecvrf_edwards25519_sha512_elligator2_test.py` and lifted
verbatim from the specification.

Copyright (c) 2020 NCC Group Plc; Provided under the MIT License.
