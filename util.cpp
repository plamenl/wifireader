#include "util.h"
unsigned short swaps( unsigned short val)
{
    return ((val & 0xff) << 8) | ((val & 0xff00) >> 8);
}

void write_swapped_bytes(ULONG bytes, FILE *fp) 
	{
	USHORT bytes1 = bytes << 16;
	USHORT bytes2 = (bytes << 8) >> 16;

	fprintf(fp,"%02x-%02x", bytes1, bytes2);
	}