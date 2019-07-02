#include "proto/tbb_parser.hpp"


#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include "llvm/Support/CommandLine.h"

using namespace llvm;
using namespace std;

cl::opt<std::string>
   basic_blocks_file("bb_trace", cl::desc("<basic_blocks.bin>"), cl::Required);

TBBParser::TBBParser(){
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  index = 0;
  tbbs = NULL;
  parse_tbb_entry(basic_blocks_file.c_str());
}

TBBParser::~TBBParser() {
  google::protobuf::ShutdownProtobufLibrary();
}

void TBBParser::parse_tbb_entry(const char *basic_blocks_file) {

  // Verify that the version of the library that we linked against is
  // compatible with the version of the headers we compiled against.

  if(tbbs != NULL)
    return;

  tbbs = new TBBBlocks();

  {
    // Read the existing address book.
    fstream input(basic_blocks_file, ios::in | ios::binary);
    if (!tbbs->ParseFromIstream(&input)) {
      return;
    }
  }

  // Optional:  Delete all global objects allocated by libprotobuf.
  // google::protobuf::ShutdownProtobufLibrary();
}

bool TBBParser::hasNext() {
  return index < tbbs->basic_blocks_size() ? true : false;
}

const ::TBBBlock& TBBParser::getNext() {
  if(index >= tbbs->basic_blocks_size())
    index = 0;

  return tbbs->basic_blocks(index++);
}
