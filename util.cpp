#include "util.h"
unsigned short swaps( unsigned short val)
{
    return ((val & 0xff) << 8) | ((val & 0xff00) >> 8);
}

void write_swapped_bytes(USHORT bytes, FILE *fp) 
	{
	USHORT bytes1 = (bytes & 0xff00) >> 8;
	USHORT bytes2 = (bytes & 0x00ff);

	fprintf(fp,"%02x-%02x", bytes2, bytes1);
	}