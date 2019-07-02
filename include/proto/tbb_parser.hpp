#ifndef TBB_PARSER_H
#define TBB_PARSER_H

#include "proto/tbb.pb.h"

class TBBParser{
private:

  void parse_tbb_entry(const char *basic_blocks_file);

  unsigned int index;

  TBBBlocks* tbbs;

public:

  TBBParser();

  ~TBBParser();

  bool hasNext();

  const ::TBBBlock& getNext();
};

#endif
