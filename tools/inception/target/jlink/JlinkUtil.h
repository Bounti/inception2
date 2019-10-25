#ifndef _JLINKUTIL_H_INCLUDED
#define _JLINKUTIL_H_INCLUDED

#if defined (__cplusplus)
extern "C" {
#endif

int JlinkConnect(unsigned short freq, unsigned int coreId);
void JlinkClose();
void JlinkResetTarget(unsigned delay);
void printTDO(const unsigned char *buf, int bitLen);

#if defined (__cplusplus)
}
#endif
#endif
