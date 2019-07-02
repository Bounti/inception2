#include "proto/tmr_parser.hpp"

#include "llvm/Support/CommandLine.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace llvm;
using namespace std;

cl::opt<std::string> dumped_mem_file("mem_trace", cl::desc("<dumped_mem.bin>"),
                                     cl::Required);

cl::opt<std::string> special_reads_file("special_mem",
                                        cl::desc("<special_reads.bin>"),
                                        cl::Required);

TMRParser::TMRParser() {
  // Verify that the version of the library that we linked against is
  // compatible with the version of the headers we compiled against.
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  parse_tmr_normal_entry();
  parse_tmr_special_entry();

  tsmr = NULL;
  tnmr = NULL;
}

TMRParser::~TMRParser() {
  // Optional:  Delete all global objects allocated by libprotobuf.
  google::protobuf::ShutdownProtobufLibrary();
}

void TMRParser::parse_tmr_normal_entry() {

  tmr_normal_reads = new TMRNormalReads();

  {
    // Read the existing address book.
    fstream input(dumped_mem_file.c_str(), ios::in | ios::binary);

    if (!tmr_normal_reads->ParseFromIstream(&input)) {
      return;
    }
  }

  // for (int i = 0; i < tmr_normal_reads->reads_size(); i++) {
  //   const ::TMRNormalMemoryRead &tmp = tmr_normal_reads->reads(i);
  //
  //   cout << "Address   : " << tmp.address() << endl;
  //   cout << "Content   : " << tmp.content() << endl;
  //   cout << "    " << endl;
  // }
  return;
}

void TMRParser::parse_tmr_special_entry() {

  tmr_special_reads = new TMRSpecialReads();

  {
    // Read the existing address book.
    fstream input(special_reads_file.c_str(), ios::in | ios::binary);
    if (!tmr_special_reads->ParseFromIstream(&input)) {
      return;
    }
  }

  // for (int i = 0; i < tmr_special_reads->reads_size(); i++) {
  //   const ::TMRSpecialMemoryRead &tmp = tmr_special_reads->reads(i);
  //
  //   cout << "Address   : " << tmp.address() << endl;
  //   cout << "    " << endl;
  // }
  return;
}

// Return true if giving address is in a mapped address range
bool TMRParser::is_mmio_address(unsigned int address) {

  // Check cached tsmr
  if (is_content_of(address, tsmr)) {
    return true;
  }

  for (int k = 0; k < tmr_special_reads->reads_size(); k++) {
    tsmr = (const TMRSpecialMemoryRead*) &(tmr_special_reads->reads(k));

    if (is_content_of(address, tsmr)) {
      return true;
    }
  }

  return false;
}

// Return true if giving address is in a mapped address range
bool TMRParser::is_local_address(unsigned int address) {

  if (tnmr != NULL && tnmr->address() == address)
    return true;

  for (int k = 0; k < tmr_normal_reads->reads_size(); k++) {
    tnmr = (TMRNormalMemoryRead *)&(tmr_normal_reads->reads(k));

    if (tnmr->address() == address)
      return true;
  }

  return false;
}

// Return true if giving address is symbolic
bool TMRParser::is_mmio_address_symbolic(unsigned int address) {
  const TMRByte* byte;
  if ((byte = resolveTMRByte(address))) {
    return (byte->has_is_symbolic() && byte->is_symbolic());
  }
  return false;
}

// Return true if giving address is concrete
bool TMRParser::is_mmio_address_concrete(unsigned int address) {
  const TMRByte* byte;
  if ((byte = resolveTMRByte(address))) {
    return byte->has_value();
  }
  return false;
}

// Return true if giving address is read only
bool TMRParser::is_mmio_address_read_only(unsigned int address) {
  const TMRByte* byte;
  if ((byte = resolveTMRByte(address))) {
    return (byte->has_is_rom() && byte->is_rom());
  }
  return false;
}

// Return true if giving address is special
bool TMRParser::is_mmio_address_special(unsigned int address) {
  const TMRByte* byte;
  if ((byte = resolveTMRByte(address))) {
    return (byte->has_is_special() && byte->is_special());
  }
  return false;
}

// Return concrete traced value for a giving address
unsigned int TMRParser::get_mmio_address_value(unsigned int address) {
  const TMRByte* byte;
  if ((byte = resolveTMRByte(address))) {
    if( byte->has_value() )
      return (unsigned int) byte->value();
  }
  return 0;
}


// Return concrete traced value for a giving address
unsigned int TMRParser::get_local_address_value(unsigned int address) {
  unsigned int result = 0;

  if (tnmr->address() == address) {
    const ::std::string& content = tnmr->content();
    memcpy(&result, content.data(), 4);
    return result;
  }

  for (int k = 0; k < tmr_normal_reads->reads_size(); k++) {
    tnmr = (const TMRNormalMemoryRead *)&(tmr_normal_reads->reads(k));

    if (tnmr->address() == address) {
      const ::std::string& content = tnmr->content();
      memcpy(&result, content.data(), 4);
      return result;
    }
  }

  //TODO: return exception so that we can stop the execution
  return 0;
}
