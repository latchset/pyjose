from libc.stdint cimport uint8_t
cimport jansson

# *********************************************************************
# standard headers

cdef extern from "stdbool.h":
    ctypedef signed char bool

# *********************************************************************
# jose

cdef extern from "jose/buf.h":
    ctypedef struct jose_buf_t:
        size_t size
        uint8_t *data


cdef extern from "jose/jwe.h":
    pass


cdef extern from "jose/jwk.h":
    ctypedef struct jose_jwk_type_t:
       pass

    ctypedef struct jose_jwk_op_t:
       pass

    ctypedef struct jose_jwk_resolver_t:
       pass

    ctypedef struct jose_jwk_generator_t:
       pass

    ctypedef struct jose_jwk_hasher_t:
       pass

    ctypedef struct jose_jwk_exchanger_t:
       pass

    bool jose_jwk_generate(jansson.json_t *jwk)


cdef extern from "jose/jws.h":
    pass
