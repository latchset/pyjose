import unittest

import jose.jwk


class JoseTests(unittest.TestCase):
    def test_jwk_generate(self):
        jwk = {'alg': 'A128GCM'}
        jose.jwk.generate(jwk)
        k = jwk.pop('k')
        self.assertTrue(k)
        self.assertEqual(jwk, {
            'alg': 'A128GCM', 'kty': 'oct',
            'key_ops': ['encrypt', 'decrypt'], 'use': 'enc'
        })
