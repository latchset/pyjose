from libc.stdlib cimport free
cimport jansson
cimport jose

import json


def jwk_generate(jwk):
    cdef jansson.json_t *cjwk = NULL
    cdef char *ret = NULL

    assert isinstance(jwk, dict)

    try:
        cjwk = jansson.json_loads(json.dumps(jwk).encode(u"UTF-8"), 0, NULL)
        assert cjwk

        assert jose.jose_jwk_generate(cjwk)

        ret = jansson.json_dumps(cjwk, 0)
        assert ret

        jwk.clear()
        jwk.update(json.loads(ret))
    finally:
        jansson.json_decref(cjwk)
        free(ret)


def jwk_clean(jwk):
    cdef jansson.json_t *cjwk = NULL
    cdef char *ret = NULL

    assert isinstance(jwk, dict)

    try:
        cjwk = jansson.json_loads(json.dumps(jwk).encode(u"UTF-8"), 0, NULL)
        assert cjwk

        assert jose.jose_jwk_clean(cjwk)

        ret = jansson.json_dumps(cjwk, 0)
        assert ret

        jwk.clear()
        jwk.update(json.loads(ret))
    finally:
        jansson.json_decref(cjwk)
        free(ret)


def jwk_allowed(jwk, req=False, use=None, op=None):
    cdef jansson.json_t *cjwk = NULL
    cdef const char *cuse = NULL
    cdef const char *cop = NULL

    assert isinstance(jwk, dict)
    assert op is None or isinstance(op, unicode)
    assert use is None or isinstance(use, unicode)

    if use is not None:
        use = use.encode(u"UTF-8")
        cuse = use

    if op is not None:
        op = op.encode(u"UTF-8")
        cop = op

    try:
        cjwk = jansson.json_loads(json.dumps(jwk).encode(u"UTF-8"), 0, NULL)
        assert cjwk

        return True if jose.jose_jwk_allowed(cjwk, req, cuse, cop) else False
    finally:
        jansson.json_decref(cjwk)


def jwk_thumbprint(jwk, hash=u"sha1"):
    cdef jansson.json_t *cjwk = NULL
    cdef char *ret = NULL

    assert isinstance(jwk, dict)
    assert isinstance(hash, unicode)

    try:
        cjwk = jansson.json_loads(json.dumps(jwk).encode(u"UTF-8"), 0, NULL)
        assert cjwk

        ret = jose.jose_jwk_thumbprint(cjwk, hash)
        assert ret

        return <bytes> ret
    finally:
        jansson.json_decref(cjwk)
        free(ret)


def jwk_exchange(prv, pub):
    cdef jansson.json_t *cprv = NULL
    cdef jansson.json_t *cpub = NULL
    cdef jansson.json_t *cout = NULL
    cdef char *ret = NULL

    assert isinstance(prv, dict)
    assert isinstance(pub, dict)

    try:
        cprv = jansson.json_loads(json.dumps(prv).encode(u"UTF-8"), 0, NULL)
        assert cprv

        cpub = jansson.json_loads(json.dumps(pub).encode(u"UTF-8"), 0, NULL)
        assert cpub

        cout = jose.jose_jwk_exchange(cprv, cpub)
        assert cout

        ret = jansson.json_dumps(cout, 0)
        assert ret

        return json.loads(ret)
    finally:
        jansson.json_decref(cprv)
        jansson.json_decref(cpub)
        free(ret)


def jws_sign(jws, jwk, sig={}):
    cdef jansson.json_t *cjws = NULL
    cdef jansson.json_t *cjwk = NULL
    cdef jansson.json_t *csig = NULL
    cdef char *ret = NULL

    assert isinstance(jws, dict)
    assert isinstance(jwk, dict)
    assert isinstance(sig, dict)

    try:
        cjws = jansson.json_loads(json.dumps(jws).encode(u"UTF-8"), 0, NULL)
        assert cjws

        cjwk = jansson.json_loads(json.dumps(jwk).encode(u"UTF-8"), 0, NULL)
        assert cjwk

        csig = jansson.json_loads(json.dumps(sig).encode(u"UTF-8"), 0, NULL)
        assert csig

        assert jose.jose_jws_sign(cjws, cjwk, csig)

        ret = jansson.json_dumps(cjws, 0)
        assert ret

        jws.clear()
        jws.update(json.loads(ret))
    finally:
        jansson.json_decref(cjws)
        jansson.json_decref(cjwk)
        jansson.json_decref(csig)
        free(ret)


def jws_verify(jws, jwk, sig=None):
    cdef jansson.json_t *cjws = NULL
    cdef jansson.json_t *cjwk = NULL
    cdef jansson.json_t *csig = NULL
    cdef char *ret = NULL

    assert isinstance(jws, dict)
    assert isinstance(jwk, dict)
    assert isinstance(sig, dict) or sig is None

    try:
        cjws = jansson.json_loads(json.dumps(jws).encode(u"UTF-8"), 0, NULL)
        assert cjws

        cjwk = jansson.json_loads(json.dumps(jwk).encode(u"UTF-8"), 0, NULL)
        assert cjwk

        if sig is not None:
            csig = jansson.json_loads(json.dumps(sig).encode(u"UTF-8"), 0, NULL)
            assert csig

        return True if jose.jose_jws_verify(cjws, cjwk, csig) else False
    finally:
        jansson.json_decref(cjws)
        jansson.json_decref(cjwk)
        jansson.json_decref(csig)


def jws_merge_header(jws):
    cdef jansson.json_t *cjws = NULL
    cdef jansson.json_t *chdr = NULL
    cdef char *ret = NULL

    assert isinstance(jws, dict)

    try:
        cjws = jansson.json_loads(json.dumps(jws).encode(u"UTF-8"), 0, NULL)
        assert cjws

        chdr = jose.jose_jws_merge_header(cjws)
        assert chdr

        ret = jansson.json_dumps(chdr, 0)
        assert ret

        return json.loads(ret)
    finally:
        jansson.json_decref(cjws)
        jansson.json_decref(chdr)
        free(ret)


def jwe_encrypt(jwe, cek, pt):
    cdef jansson.json_t *cjwe = NULL
    cdef jansson.json_t *ccek = NULL
    cdef char *ret = NULL

    assert isinstance(jwe, dict)
    assert isinstance(cek, dict)
    assert isinstance(pt, bytes)

    try:
        cjwe = jansson.json_loads(json.dumps(jwe).encode(u"UTF-8"), 0, NULL)
        assert cjwe

        ccek = jansson.json_loads(json.dumps(cek).encode(u"UTF-8"), 0, NULL)
        assert cjwe

        assert jose.jose_jwe_encrypt(cjwe, ccek, pt, len(pt))

        ret = jansson.json_dumps(cjwe, 0)
        assert ret

        jwe.clear()
        jwe.update(json.loads(ret))
    finally:
        jansson.json_decref(cjwe)
        jansson.json_decref(ccek)
        free(ret)


def jwe_wrap(jwe, cek, jwk, rcp={}):
    cdef jansson.json_t *cjwe = NULL
    cdef jansson.json_t *ccek = NULL
    cdef jansson.json_t *cjwk = NULL
    cdef jansson.json_t *crcp = NULL
    cdef char *ret = NULL

    assert isinstance(jwe, dict)
    assert isinstance(cek, dict)
    assert isinstance(jwk, dict)
    assert isinstance(rcp, dict)

    try:
        cjwe = jansson.json_loads(json.dumps(jwe).encode(u"UTF-8"), 0, NULL)
        assert cjwe

        ccek = jansson.json_loads(json.dumps(cek).encode(u"UTF-8"), 0, NULL)
        assert cjwe

        cjwk = jansson.json_loads(json.dumps(jwk).encode(u"UTF-8"), 0, NULL)
        assert cjwk

        crcp = jansson.json_loads(json.dumps(rcp).encode(u"UTF-8"), 0, NULL)
        assert crcp

        assert jose.jose_jwe_wrap(cjwe, ccek, cjwk, crcp)

        ret = jansson.json_dumps(cjwe, 0)
        assert ret

        jwe.clear()
        jwe.update(json.loads(ret))

        free(ret)
        ret = NULL

        ret = jansson.json_dumps(ccek, 0)
        assert ret

        cek.clear()
        cek.update(json.loads(ret))
    finally:
        jansson.json_decref(cjwe)
        jansson.json_decref(ccek)
        jansson.json_decref(cjwk)
        jansson.json_decref(crcp)
        free(ret)


def jwe_unwrap(jwe, jwk, rcp=None):
    cdef jansson.json_t *cjwe = NULL
    cdef jansson.json_t *cjwk = NULL
    cdef jansson.json_t *crcp = NULL
    cdef jansson.json_t *ccek = NULL
    cdef char *ret = NULL

    assert isinstance(jwe, dict)
    assert isinstance(jwk, dict)
    assert isinstance(rcp, dict) or rcp is None

    try:
        cjwe = jansson.json_loads(json.dumps(jwe).encode(u"UTF-8"), 0, NULL)
        assert cjwe

        cjwk = jansson.json_loads(json.dumps(jwk).encode(u"UTF-8"), 0, NULL)
        assert cjwk

        if rcp is not None:
            crcp = jansson.json_loads(json.dumps(rcp).encode(u"UTF-8"), 0, NULL)
            assert crcp

        ccek = jose.jose_jwe_unwrap(cjwe, cjwk, crcp)
        assert ccek

        ret = jansson.json_dumps(ccek, 0)
        assert ret

        return json.loads(ret)
    finally:
        jansson.json_decref(cjwe)
        jansson.json_decref(cjwk)
        jansson.json_decref(crcp)
        jansson.json_decref(ccek)
        free(ret)


def jwe_decrypt(jwe, cek):
    cdef jansson.json_t *cjwe = NULL
    cdef jansson.json_t *ccek = NULL
    cdef jose.jose_buf_t *pt = NULL

    assert isinstance(jwe, dict)
    assert isinstance(cek, dict)

    try:
        cjwe = jansson.json_loads(json.dumps(jwe).encode(u"UTF-8"), 0, NULL)
        assert cjwe

        ccek = jansson.json_loads(json.dumps(cek).encode(u"UTF-8"), 0, NULL)
        assert ccek

        pt = jose.jose_jwe_decrypt(cjwe, ccek)
        assert pt

        return pt.data[:pt.size]
    finally:
        jansson.json_decref(cjwe)
        jansson.json_decref(ccek)
        jose.jose_buf_decref(pt)


def jwe_merge_header(jwe, rcp):
    cdef jansson.json_t *cjwe = NULL
    cdef jansson.json_t *crcp = NULL
    cdef jansson.json_t *chdr = NULL
    cdef char *ret = NULL

    assert isinstance(jwe, dict)
    assert isinstance(rcp, dict)

    try:
        cjwe = jansson.json_loads(json.dumps(jwe).encode(u"UTF-8"), 0, NULL)
        assert cjwe

        crcp = jansson.json_loads(json.dumps(rcp).encode(u"UTF-8"), 0, NULL)
        assert cjwe

        chdr = jose.jose_jwe_merge_header(cjwe, crcp)
        assert chdr

        ret = jansson.json_dumps(chdr, 0)
        assert ret

        return json.loads(ret)
    finally:
        jansson.json_decref(cjwe)
        jansson.json_decref(crcp)
        jansson.json_decref(chdr)
        free(ret)


def from_compact(compact):
    cdef jansson.json_t *cjose = NULL
    cdef char *ret = NULL

    assert isinstance(compact, str)

    try:
        cjose = jose.jose_from_compact(compact)
        assert cjose

        ret = jansson.json_dumps(cjose, 0)
        assert ret

        return json.loads(ret)
    finally:
        jansson.json_decref(cjose)
        free(ret)


def to_compact(flat):
    cdef jansson.json_t *cjose = NULL
    cdef char *ret = NULL

    assert isinstance(flat, dict)

    try:
        cjose = jansson.json_loads(json.dumps(flat).encode(u"UTF-8"), 0, NULL)
        assert cjose

        ret = jose.jose_to_compact(cjose)
        assert ret

        return <bytes> ret
    finally:
        jansson.json_decref(cjose)
        free(ret)
