# Verifiable Random Function (VRF)

A simple and self-contained Python 3 reference implementation of the
[draft-irtf-cfrg-vrf-06](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06)
specification corresponding to the ECVRF-EDWARDS25519-SHA512-Elligator2 
ciphersuite configuration. This code is suitable for demonstration, 
exploration and the generation of test vectors to aid porting efforts.
Significant portions of the lower-level ed25519-related operations 
were directly adapted from those provided in [Bernstein's](https://ed25519.cr.yp.to/) 
sample [ed25519.py](https://ed25519.cr.yp.to/python/ed25519.py) code.

> **Please note:** This code is alpha-quality and is not suitable for 
> production. While a limited testing infrastructure is provided, the 
> code may be incomplete, inefficient, incorrect and/or insecure. 
> Specifically, both the algorithms within the code and (the use of) 
> Python's big integers are clearly not constant time and thus 
> introduce timing side channels.
>
> The code has not undergone a security audit; use at your own risk.

The `ecvrf_edwards25519_sha512_elligator2.py` file retains a
significant amount of documentation extracted from the specification
placed alongside each relevant code statement to aid in understanding.


## Quick start

As the code has no dependencies beyond Python 3.7+, getting started is 
very simple:

    git clone https://github.com/nccgroup/draft-irtf-cfrg-vrf-06.git
    cd ./draft-irtf-cfrg-vrf-06
    
    # Run the simple demo
    python3 demo.py
    
    # Run three simple self-tests, then echo 3 instrumented test cases
    python3 ecvrf_edwards25519_sha512_elligator2_test.py
    
Here is an excerpt from `demo.py` showing example usage:

    # Alice generates a secret and public key pair
    secret_key = secrets.token_bytes(nbytes=32)
    public_key = ecvrf_edwards25519_sha512_elligator2.get_public_key(secret_key)

    # Alice generates a beta_string commitment to share with Bob
    alpha_string = b'I bid $100 for the horse named IntegrityChain'
    p_status, pi_string = ecvrf_edwards25519_sha512_elligator2.ecvrf_prove(secret_key, alpha_string)
    b_status, beta_string = ecvrf_edwards25519_sha512_elligator2.ecvrf_proof_to_hash(pi_string)

    #
    # Alice initially shares ONLY the beta_string with Bob
    #

    # Later, Bob validates Alice's subsequently shared public_key, pi_string, and alpha_string
    result, beta_string2 = ecvrf_edwards25519_sha512_elligator2.ecvrf_verify(public_key, pi_string, alpha_string)
    if p_status == "VALID" and b_status == "VALID" and result == "VALID" and beta_string == beta_string2:
        print("Commitment verified")


## API

A very simple API is provided as follows:

~~~python
# Section 5.1. ECVRF Proving
def ecvrf_prove(sk, alpha_string):
    """
    Input:
        sk - VRF private key (32 bytes)
        alpha_string - input alpha, an octet string
    Output:
        ("VALID", pi_string) - where pi_string is the VRF proof, octet string of length ptLen+n+qLen
        (80) bytes, or ("INVALID", []) upon failure
    """
...


# Section 5.2. ECVRF Proof To Hash
def ecvrf_proof_to_hash(pi_string):
    """
    Input:
        pi_string - VRF proof, octet string of length ptLen+n+qLen (80) bytes
    Output:
        ("VALID", beta_string) where beta_string is the VRF hash output, octet string
        of length hLen (64) bytes, or ("INVALID", []) upon failure
    Important note:
        ECVRF_proof_to_hash should be run only on pi_string that is known to have been
        produced by ECVRF_prove, or from within ECVRF_verify as specified in Section 5.3.
    """
...


# Section 5.3. ECVRF Verifying
def ecvrf_verify(y, pi_string, alpha_string):
    """
    Input:
        y - public key, an EC point as bytes
        pi_string - VRF proof, octet string of length ptLen+n+qLen (80) bytes
        alpha_string - VRF input, octet string
    Output:
        ("VALID", beta_string), where beta_string is the VRF hash output, octet string
        of length hLen (64) bytes; or ("INVALID", []) upon failure
    """
...
~~~


## Testing

The code is sensitized to the presence of a `test_dict` in the `globals()` space.
If present, the code asserts against values in the dict as well as samples those
same values. This allows for checking intermediate calculations as well as generating
test vectors to aid in porting. If the `test_dict` is not present, the code runs
unhindered. Examples of this are in the testing file.

All testcases are in `ecvrf_edwards25519_sha512_elligator2_test.py` and lifted
verbatim from the specification.

Copyright (c) 2020 Eric Schorn, NCC Group Plc; Provided under the MIT License.
