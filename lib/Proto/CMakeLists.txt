#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
# add_subdirectory(Protobuf)
# Protobuf build
# This file generate the protobuf-based parsing library
INCLUDE(FindProtobuf)

FIND_PACKAGE(Protobuf REQUIRED)

SET(GENERATED_DIR "${CMAKE_SOURCE_DIR}/include/proto")
SET(CMAKE_CURRENT_BINARY_DIR ${GENERATED_DIR})

include_directories(${PROTOBUF_INCLUDE_DIR})
include_directories(${GENERATED_DIR})

PROTOBUF_GENERATE_CPP(PROTO_SRC1 PROTO_HEADER1 ./tbb.proto)
PROTOBUF_GENERATE_CPP(PROTO_SRC2 PROTO_HEADER2 ./tmr.proto)

SET_SOURCE_FILES_PROPERTIES(${PROTO_SRC1} ${PROTO_HEADER1} PROPERTIES GENERATED TRUE)
SET_SOURCE_FILES_PROPERTIES(${PROTO_SRC2} ${PROTO_HEADER2} PROPERTIES GENERATED TRUE)

klee_add_component(kleeProto
  tbb_parser.cpp
  tmr_parser.cpp
  ${PROTO_SRC1}
  ${PROTO_SRC2}
)

target_link_libraries(kleeProto PUBLIC ${PROTOBUF_LIBRARY})
