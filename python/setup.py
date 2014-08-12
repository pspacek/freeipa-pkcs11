from distutils.core import setup, Extension
from distutils.sysconfig import get_python_inc
import sys
import os

python_header = os.path.join(get_python_inc(plat_specific=0), 'Python.h')
if not os.path.exists(python_header):
    sys.exit("Cannot find Python development packages that provide Python.h")

module = Extension('ipa_pkcs11',
                   define_macros = [],
                   include_dirs = [],
                   libraries = ['dl', 'crypto'],
                   library_dirs = [],
                   extra_compile_args = [
                       '-std=c99',
                       '-I/usr/include/p11-kit-1/p11-kit',
                       '-ggdb3',
                       '-O2',
                       '-W', 
                       '-pedantic',
                       '-Wall',
                       '-Wno-unused-parameter',
                       '-Wbad-function-cast',
                   ],
                   sources = ['ipa_pkcs11.c', 'library.c'])

setup(name='ipa_pkcs11',
      version = '0.1',
      description = 'FreeIPA pkcs11 utils',
      author = 'Martin Basti, Petr Spacek',
      email = 'mbasti@redhat.com, pspacek@redhat.com',
      license = 'GPLv2+',
      url='http://www.freeipa.org',  # TODO add more specific address
      long_description = """
      FreeIPA key manipulation utils.
""",
      ext_modules = [module])
