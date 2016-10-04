# -*- coding: utf-8 -*-
# Copyright 2016 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""JSON Web Key (JWK)
"""
from __future__ import absolute_import

from . import _jose


def generate(jwk):
    return _jose.jwk_generate(jwk)


def clean(jwk):
    return _jose.jwk_clean(jwk)


def allowed(jwk, req=False, use=None, op=None):
    return _jose.jwk_allowed(jwk, req, use, op)


def thumbprint(jwk, hash=u"sha1"):
    return _jose.jwk_thumbprint(jwk, hash)


def exchange(prv, pub):
    return _jose.jwk_exchange(prv, pub)
