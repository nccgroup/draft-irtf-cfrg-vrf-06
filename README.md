# Verifiable Random Function

A simple and self-contained Python3 reference implementation of the
[draft-irtf-cfrg-vrf-05](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-05)
specification corresponding to the ECVRF-EDWARDS25519-SHA512-Elligator2 
ciphersuite configuration. This code is suitable for demonstration, 
exploration and the generation of test vectors to aid porting.
Significant portions  of the lower-level ed25519-related operations 
were directly adapted from that provided in Appendex A of
[RFC 8032](https://tools.ietf.org/html/rfc8032)

> **Please note:** *This code is alpha-quality and not suitable for production.
> It is likely incomplete, inefficient, incorrect and/or insecure.*

The `ecvrf_edwards25519_sha512_elligator2.py` file retains a
significant amount of documentation extracted from the specification
to aid in understanding, and provides a simple API as follows:

~~~python
# Section 5.1. ECVRF Proving
def ecvrf_prove(SK, alpha_string, test_dict=None):
    """
    Input:
        SK - VRF private key
        alpha_string - input alpha, an octet string
        test_dict - optional dict of samples to assert and/or record
    Output:
        pi_string - VRF proof, octet string of length ptLen+n+qLen
        If a test_dict is supplied, one will be returned
    """
...


# Section 5.2. ECVRF Proof To Hash
def ecvrf_proof_to_hash(pi_string, test_dict=None):
    """
    Input:
        pi_string - VRF proof, octet string of length ptLen+n+qLen
        test_dict - optional dict of samples to assert and/or record
    Output:
        "INVALID", or beta_string - VRF hash output, octet string of length hLen
        If a test_dict is supplied, one will be returned
    Important note:
        ECVRF_proof_to_hash should be run only on pi_string that is known to have been
        produced by ECVRF_prove, or from within ECVRF_verify as specified in Section 5.3.
    """
...


# Section 5.3. ECVRF Verifying
def ecvrf_verify(Y, pi_string, alpha_string, test_dict=None):
    """
    Input:
        Y - public key, an EC point
        pi_string - VRF proof, octet string of length ptLen+n+qLen
        alpha_string - VRF input, octet string
        test_dict - optional dict of samples to assert and/or record
    Output:
        ("VALID", beta_string), where beta_string is the VRF hash output, octet string
        of length hLen; or "INVALID"
        If a test_dict is supplied, one will be returned
    """
...
~~~

...more text...
