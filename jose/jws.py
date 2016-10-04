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
"""JSON Web Signature (JWS)
"""
from __future__ import absolute_import

from . import _jose


def sign(jws, jwk, sig=None):
    return _jose.jws_sign(jws, jwk, sig)


def verify(jws, jwk, sig=None):
    return _jose.jws_verify(jws, jwk, sig)


def merge_header(jws):
    return _jose.jws_merge_header(jws)
