project('ot_cpp', 'cpp', version: '0.0.1')

zlib = dependency('zlib', version: '1.3.1')
rapidcheck = dependency('rapidcheck')
libsodium = dependency('libsodium', version: '1.0.19')

add_global_arguments('-UNDEBUG', language : 'cpp')

ot_lib = declare_dependency(
  sources: [],
  include_directories: 'include',
  dependencies: libsodium
)

test_exe = executable('maintest', 'test/main.cpp', dependencies : [libsodium, ot_lib])
test('test_exe', test_exe)

# executable(
#   'runner',
#   sources: ['test/main.cpp'],
#   dependencies: [libsodium, ot_lib],
# )
