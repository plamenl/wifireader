#include <stdio.h>
#include <Windows.h>

unsigned short swaps( unsigned short val);
void write_swapped_bytes(USHORT bytes, FILE *fp);

typedef struct {
	CHAR signal_level;
	USHORT freq;
} radio_data;
