#ifndef TMR_PARSER_H
#define TMR_PARSER_H

#include "proto/tmr.pb.h"

class TMRParser {
private:
  void parse_tmr_entry();

  unsigned int index;

  TMRSpecialReads *tmr_special_reads;

  TMRNormalReads *tmr_normal_reads;

  // Last cached request
  const TMRSpecialMemoryRead *tsmr;
  const TMRNormalMemoryRead *tnmr;

  void parse_tmr_normal_entry();

  void parse_tmr_special_entry();

  bool is_content_of(unsigned int address, const TMRSpecialMemoryRead *_tsmr) {
    if (_tsmr != NULL && (address >= _tsmr->address()) &&
        (address < (_tsmr->address() + _tsmr->tmr_bytes_size()))) {
      return true;
    } else {
      return false;
    }
  }

  const TMRByte* resolveTMRByte(unsigned int address) {
    // Check cached tsmr
    if (tsmr != NULL && is_content_of(address, tsmr)) {
      int offset = address - tsmr->address();
      const ::TMRByte &tmr_byte = tsmr->tmr_bytes(offset);
      return &tmr_byte;
    }

    for (int k = 0; k < tmr_special_reads->reads_size(); k++) {
      tsmr = &(tmr_special_reads->reads(k));

      if (is_content_of(address, tsmr)) {
        int offset = address - tsmr->address();
        const ::TMRByte &tmr_byte = tsmr->tmr_bytes(offset);
        return &tmr_byte;
      }
    }

    return NULL;
  }

public:
  TMRParser();

  ~TMRParser();

  /*
   * To reduce performance overload we chache the last accessed tmr object
   */

  // Return true if giving address is in a mapped address range
  bool is_mmio_address(unsigned int address);

  // Return true if giving address is in a local address
  bool is_local_address(unsigned int address);

  bool is_mapped_address_concrete(unsigned int address);

  // Return true if giving address is symbolic
  bool is_mmio_address_symbolic(unsigned int address);

  // Return true if giving address is concrete
  bool is_mmio_address_concrete(unsigned int address);

  // Return true if giving address is read only
  bool is_mmio_address_read_only(unsigned int address);

  // Return true if giving address is special
  bool is_mmio_address_special(unsigned int address);

  // Return concrete traced value for a giving mmio address
  unsigned int get_mmio_address_value(unsigned int address);

  // Return traced value for a giving local address
  unsigned int get_local_address_value(unsigned int address);
};

#endif
