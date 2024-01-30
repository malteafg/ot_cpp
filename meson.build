project('ot_cpp', 'cpp', version: '0.0.1')

zlib = dependency('zlib', version: '1.3')
rapidcheck = dependency('rapidcheck')
libsodium = dependency('libsodium', version: '1.0.18')

add_global_arguments('-UNDEBUG', language : 'cpp')

crylib = shared_library('crylib', sources: ['crylib/crypto.cpp', 'crylib/rand.cpp'], dependencies: libsodium)

executable('runner', 'test/main.cpp', include_directories: 'crylib', dependencies: libsodium, link_with: crylib)
