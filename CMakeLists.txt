cmake_minimum_required(VERSION 3.16)

if(POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()
if(POLICY CMP0077)
  cmake_policy(SET CMP0077 NEW)
endif()

# Fix "unrecognized escape" issues when passing CMAKE_MODULE_PATH on Windows.
file(TO_CMAKE_PATH "${CMAKE_MODULE_PATH}" CMAKE_MODULE_PATH)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

project(xrpl)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# make GIT_COMMIT_HASH define available to all sources
find_package(Git)
if(Git_FOUND)
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=${CMAKE_CURRENT_SOURCE_DIR}/.git describe --always --abbrev=40
        OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE gch)
    if(gch)
        set(GIT_COMMIT_HASH "${gch}")
        message(STATUS gch: ${GIT_COMMIT_HASH})
        add_definitions(-DGIT_COMMIT_HASH="${GIT_COMMIT_HASH}")
    endif()
endif() #git

if(thread_safety_analysis)
  add_compile_options(-Wthread-safety -D_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS -DRIPPLE_ENABLE_THREAD_SAFETY_ANNOTATIONS)
  add_compile_options("-stdlib=libc++")
  add_link_options("-stdlib=libc++")
endif()

include (CheckCXXCompilerFlag)
include (FetchContent)
include (ExternalProject)
include (CMakeFuncs) # must come *after* ExternalProject b/c it overrides one function in EP
if (target)
  message (FATAL_ERROR "The target option has been removed - use native cmake options to control build")
endif ()

include(RippledSanity)
include(RippledVersion)
include(RippledSettings)
# this check has to remain in the top-level cmake
# because of the early return statement
if (packages_only)
  if (NOT TARGET rpm)
    message (FATAL_ERROR "packages_only requested, but targets were not created - is docker installed?")
  endif()
  return ()
endif ()
include(RippledCompiler)
include(RippledInterface)

option(only_docs "Include only the docs target?" FALSE)
include(RippledDocs)
if(only_docs)
  return()
endif()

###

include(deps/Boost)
# set(OPENSSL_ROOT_DIR "/usr")
# set(OPENSSL_INCLUDE_DIR "/usr/include")
# set(OPENSSL_LIBRARIES "/usr/lib/x86_64-linux-gnu/libssl.so;/usr/lib/x86_64-linux-gnu/libcrypto.so")
# find_package(OpenSSL REQUIRED)
set(OPENSSL_USE_STATIC_LIBS OFF)
set(OPENSSL_ROOT_DIR /usr)
find_package(OpenSSL 3.0.2 REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
set_target_properties(OpenSSL::SSL PROPERTIES
  INTERFACE_COMPILE_DEFINITIONS OPENSSL_NO_SSL2
)
set(SECP256K1_INSTALL TRUE)
add_subdirectory(external/secp256k1)
add_library(secp256k1::secp256k1 ALIAS secp256k1)
add_subdirectory(external/ed25519-donna)
add_subdirectory(external/antithesis-sdk)
find_package(gRPC REQUIRED)
find_package(lz4 REQUIRED)
# Target names with :: are not allowed in a generator expression.
# We need to pull the include directories and imported location properties
# from separate targets.
find_package(LibArchive REQUIRED)
find_package(SOCI REQUIRED)
find_package(SQLite3 REQUIRED)

option(rocksdb "Enable RocksDB" ON)
if(rocksdb)
  find_package(RocksDB REQUIRED)
  set_target_properties(RocksDB::rocksdb PROPERTIES
    INTERFACE_COMPILE_DEFINITIONS RIPPLE_ROCKSDB_AVAILABLE=1
  )
  target_link_libraries(ripple_libs INTERFACE RocksDB::rocksdb)
endif()

find_package(nudb REQUIRED)
find_package(date REQUIRED)
find_package(xxHash REQUIRED)

# Libsnark
# ---------------------------- Curve Selection ---------------------------------
# Supported by upstream libsnark:
#   • ALT_BN128  – alt-bn128 pairing curve
#   • BN128      – (default) bn128 pairing curve
#   • EDWARDS    – edwards25519
#   • MNT4       – MNT4-298
#   • MNT6       – MNT6-298
add_definitions(-DCURVE_BN128)

# ---------------------------- Parallel proving --------------------------------
# libsnark's CMakeLists sets -fopenmp/-DMULTICORE in ITS OWN subdirectory scope,
# which the parent project never sees. That is not enough here: the Groth16
# prover is a TEMPLATE (r1cs_gg_ppzksnark_prover, see BatchCircuitProver.cpp)
# instantiated in OUR translation units, so its `#ifdef MULTICORE` OpenMP
# pragmas are compiled with RIPPLED's flags, not libsnark's. Without this block
# the pragmas vanish and proving runs single-threaded no matter what
# -DMULTICORE=ON is passed — measured: 1 thread, 100% of one core.
if(MULTICORE)
  find_package(OpenMP)
  if(OpenMP_CXX_FOUND)
    add_definitions(-DMULTICORE=1)
    # -fopenmp must be a COMPILE option on our own targets, not merely an
    # INTERFACE link dependency. Linking OpenMP::OpenMP_CXX alone pulls in
    # libgomp but leaves -fopenmp off the compile line, so every `#pragma omp`
    # in the instantiated prover templates is silently ignored — while
    # MULTICORE=1 still switches on the multicore code paths. That combination
    # is worse than serial: it takes the parallel branch with no parallelism.
    add_compile_options(${OpenMP_CXX_FLAGS})
    target_link_libraries(ripple_libs INTERFACE OpenMP::OpenMP_CXX)
    message(STATUS "Parallel proving ENABLED (OpenMP + MULTICORE=1)")
  else()
    message(WARNING "MULTICORE=ON but OpenMP not found — proving stays serial")
  endif()
endif()

# Header search paths
include_directories(
  dependencies
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/external/libsnark
  ${CMAKE_CURRENT_SOURCE_DIR}/external/libsnark/depends/libff
  ${CMAKE_CURRENT_SOURCE_DIR}/external/libsnark/depends/libfqfft)

add_subdirectory(external/libsnark)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/libsnark/depends/ate-pairing)
add_library(libff_profiling_stub STATIC external/libsnark/depends/libff/libff/common/libff_profiling_stub.cpp)


target_link_libraries(ripple_libs INTERFACE
  snark                    # CMake target for libsnark ( -l:libsnark.a)
  ff                       # CMake target for libff ( -l:libff.a) Making the code cleaner and better in practice
  ed25519::ed25519
  lz4::lz4
  OpenSSL::Crypto
  OpenSSL::SSL
  secp256k1::secp256k1
  soci::soci
  SQLite::SQLite3
  libff_profiling_stub
  gmp                      # or -lgmp 
  gmpxx                    # or -lgmpxx 
  zm             # is there no target??
)
message(STATUS "Successfully linked ripple_libs with snark and ff libraries.")
# Work around changes to Conan recipe for now.
if(TARGET nudb::core)
  set(nudb nudb::core)
elseif(TARGET NuDB::nudb)
  set(nudb NuDB::nudb)
else()
  message(FATAL_ERROR "unknown nudb target")
endif()
target_link_libraries(ripple_libs INTERFACE ${nudb})

if(coverage)
  include(RippledCov)
endif()

set(PROJECT_EXPORT_SET RippleExports)
include(RippledCore)
include(RippledInstall)
include(RippledValidatorKeys)
