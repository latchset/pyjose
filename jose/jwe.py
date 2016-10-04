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
"""JSON Web Encryption (JWE)
"""
from __future__ import absolute_import

from . import _jose


def encrypt(jwe, cek, pt):
    return _jose.jwe_encrypt(jwe, cek, pt)


def wrap(jwe, cek, jwk, rcp=None):
    return _jose.jwe_wrap(jwe, cek, jwk, rcp)


def unwrap(jwe, jwk, rcp=None):
    return _jose.jwe_unwrap(jwe, jwk, rcp)


def decrypt(jwe, cek):
    return _jose.jwe_decrypt(jwe, cek)


def merge_header(jwe, rcp):
    return _jose.jwe_merge_header(jwe, rcp)
