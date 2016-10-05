import os

from setuptools import setup
from setuptools.extension import Extension
from Cython.Build import cythonize

JOSE_DIR = '../jose'
JOSE_LIBRARY_DIR = os.path.join(JOSE_DIR, '.libs')

extensions = [
    Extension(
        'jose._jose',
        sources=['_jose.pyx'],
        depends=['jansson.pxd', 'jose.pxd', 'setup.py'],
        include_dirs=[JOSE_DIR],
        libraries=['jose', 'jose-openssl', 'jose-zlib'],
        library_dirs=[JOSE_LIBRARY_DIR],
        extra_link_args=['-Wl,-rpath,' + JOSE_LIBRARY_DIR],
    ),
]

setup(
    name='jose',
    description='Cython wrapper for libjose',
    ext_modules=cythonize(extensions),
    version='4',
    license='Apache 2.0',
    maintainer='Latchset Contributors',
    maintainer_email='cheimes@redhat.com',
    url='https://github.com/latchset/pyjose',
    packages=['jose'],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Programming Language :: Cython',
        'Programming Language :: C',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
