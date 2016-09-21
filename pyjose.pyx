cimport pyjose
cimport jansson
from libc cimport stdio

cdef jansson.json_t *jwk

jwk = jansson.json_pack("{s:s}", "alg", "A128GCM")
pyjose.jose_jwk_generate(jwk)
jansson.json_dumpf(jwk, stdio.stderr, 0)
