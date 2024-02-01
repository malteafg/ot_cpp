project('ot_cpp', 'cpp', version: '0.0.1')

zlib = dependency('zlib', version: '1.3')
rapidcheck = dependency('rapidcheck')
libsodium = dependency('libsodium', version: '1.0.18')

add_global_arguments('-UNDEBUG', language : 'cpp')

crylib = shared_library(
  'crylib',
  sources: ['crylib/src/crypto.cpp', 'crylib/src/rand.cpp'],
  include_directories: ['crylib/include'],
  dependencies: libsodium
)

executable(
  'runner',
  sources: ['test/src/main.cpp'],
  include_directories: ['crylib/include'],
  dependencies: libsodium,
  link_with: crylib
)
