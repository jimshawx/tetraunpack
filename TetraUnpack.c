#include <assert.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void disassemble_buffer(unsigned char *b, unsigned int len);
extern void dump_buffer(unsigned char *b, unsigned int len);
static void unpack(unsigned char *b);

static void swap(unsigned int *w)
{
	*w = (*w >> 24) | (*w << 24) | ((*w >> 8) & 0xff00) | ((*w << 8) & 0xff0000);
}

int main(int argc, char **argv)
{
	char *fname;
	if (argc <= 1)
	{
		fname = "samples/VF-VenloPartyDemo.exe";
		//fname = "samples/Tetra_Pack_v2.2.exe";
	}
	else
		fname = argv[1];

	FILE *f;
	if (fopen_s(&f, fname, "rb") == 0)
	{
		unsigned int l;
		
		fseek(f, 0, SEEK_END);
		long len = ftell(f);
		fprintf(stdout, "file size is %ld\n", len);
		
		fseek(f, 0, SEEK_SET);

		// HUNK_HEADER 0x3F3
		fread(&l, 1, sizeof l, f);
		swap(&l);
		if (l == 0x3F3)
		{
			//strings
			fread(&l, 1, sizeof l, f);
			if (l != 0)
			{
				swap(&l);
				for (unsigned int i = 0; i < l; i++)
					fread(&l, 1, sizeof l, f);
			}
			
			unsigned int num_hunks, first_hunk, last_hunk;

			fread(&num_hunks, 1, sizeof num_hunks, f);	swap(&num_hunks);
			fread(&first_hunk, 1, sizeof first_hunk, f);	swap(&first_hunk);
			fread(&last_hunk, 1, sizeof last_hunk, f);	swap(&last_hunk);

			fprintf(stdout, "hunk count %u, first load %u, last_load %u\n", num_hunks, first_hunk, last_hunk);

			const unsigned int num_sizes = last_hunk - first_hunk + 1;
			for (unsigned int i = 0; i < num_sizes; i++)
			{
				fread(&l, 1, sizeof l, f);
				swap(&l);
				unsigned int flags = l >> 30;
				if (flags == 3)
				{
					fread(&flags, 1, sizeof flags, f);
					swap(&flags);
				}
				fprintf(stdout, "hunk %u size is %u %08X, flags %08X\n", i, 4*(l%0x3fffffff), 4 * (l % 0x3fffffff), flags);
			}

			for (unsigned int i = 0; i < num_hunks; i++)
			{
				unsigned int hunk_type;
				fread(&hunk_type, 1, sizeof hunk_type, f);
				swap(&hunk_type);

				if (hunk_type == 0x3E9)/* HUNK_CODE */
				{
					long t = ftell(f);
					
					unsigned int num_longs;
					fread(&num_longs, 1, sizeof num_longs, f);
					swap(&num_longs);

					fprintf(stdout, "hunk %u is %u, %08X, bytes of CODE\n", i, num_longs*4, num_longs * 4);

					unsigned char *b;
					unsigned int *c;
					b = c = malloc(num_longs * 4);
					
					for (unsigned int j = 0; j < num_longs; j++)
					{
						fread(&l, 1, sizeof l, f);
						*c++ = l;
						swap(&l);

						//if (j != 0 && j % 8 == 0) fputc('\n', stdout);
						//fprintf(stdout, "%04X %04X ", l >> 16, l & 0xffff);
					}
					//dump_buffer(b, num_longs * 4);
					//disassemble_buffer(b, num_longs * 4);

					if (!strncmp((char*)b+0xc4, " TETRAGON ", 10))
						unpack(b);
					else
						fprintf(stderr, "this hunk is not TETRAGON packed");
				}
				else if (hunk_type == 0x3EA)/* HUNK_DATA */
				{
					unsigned int num_longs;
					fread(&num_longs, 1, sizeof num_longs, f);
					swap(&num_longs);

					fprintf(stdout, "hunk %u is %u, %08X, bytes of DATA\n", i, num_longs * 4, num_longs * 4);

					for (unsigned int j = 0; j < num_longs; j++)
					{
						fread(&l, 1, sizeof l, f);
						swap(&l);

						if (j != 0 && j % 8 == 0) fputc('\n', stdout);
						fprintf(stdout, "%04X %04X ", l >> 16, l & 0xffff);
					}
				}
				else if (hunk_type == 0x3EB)/* HUNK_BSS */
				{
					unsigned int num_longs;
					fread(&num_longs, 1, sizeof num_longs, f);
					swap(&num_longs);

					fprintf(stdout, "hunk %u is %u, %08X, bytes of BSS\n", i, num_longs * 4, num_longs * 4);
				}
				else
				{
					fprintf(stderr, "file contains unknown hunk 0x%08X\n", hunk_type);
				}
			}
		}
		else
		{
			fprintf(stderr, "file doesn't start with a HUNK_HEADER\n");
		}
		
		fclose(f);
	}

	return 0;
}

static unsigned char *A0, *A1, *A2, *A4;
static unsigned int D0, D1, D2, D3, D4, D7;
static unsigned char C,X;
static void get_next_long_in_D0(void);
static void get_next_D1_bits_in_D2(void);
static void RLE(unsigned char *src, unsigned char *dst, unsigned int length);
static unsigned int bswap(unsigned int s) { return (s >> 24) | (s << 24) | ((s >> 8) & 0xff00) | ((s << 8) & 0xff0000); }
static void unpack(unsigned char *source)
{
	A1 = source + 0x100;//source data address which starts at 0x100 past start of code
	A4 = 0x3e742;//unpack target address it's moved from the LEA of the RLE section.
	A0 = A4;
	A0 += 0x193b0;//source filesize - 256, i.e. size of compressed data following the unpacker : this number is plugged in

	//if (A1 <= A4)
	{
		A0 = A1;
		A0 += 0x193b0;//filesize - 256, it's added from the A4+= ADDA.L instruction above
	}
	//else
	//{
	//	do
	//	{
	//		*A4++ = *A1++;
	//	} while (A0 < A4);
	//}
	
	A1 = 0x44941;//what? : this number is plugged in

	//A0 is pointing at end of packed data
	
	A0 -= 4; A2 = bswap(*(unsigned int *)A0);//A0 will be source+0x193b0+0x100, A2 is 1edb7
	A2 += (uintptr_t)A1;//A2 is now 636f8
	A0 -= 4; D0 = bswap(*(unsigned int *)A0);

	//A0 is pointing at end of packed data
	//A1 is pointing at the beginning of the unpack location for 1st step of compression
	//A2 is pointing at end of unpack location
	//A4 is pointing at start of unpack location

	int unpacked_size = A2 - A4;
	int unpacked_step1_size = A1 - A4;
	A4 = malloc(unpacked_size);
	A2 = A4 + unpacked_size;
	A1 = A4 + unpacked_step1_size;
	
	//1st step of compression - looks like some kind of Huffman-style decompressor
	
	//0036
	do
	{
		//0036
		X = C = D0 & 1;
		D0 >>= 1;
		if (D0 == 0) get_next_long_in_D0();
		if (C) goto iA8;

		D1 = 8;
		D3 = 1;

		//0042
		X = C = D0 & 1;
		D0 >>= 1;
		if (D0 == 0) get_next_long_in_D0();
		if (C) goto i86;

		D1 = 3;
		D4 = 0;

		//004E
		for (;;)
		{
			get_next_D1_bits_in_D2();
			D3 = D2 + D4;
			do
			{
				int count = 7;
				//0056
				do
				{
					X = C = D0 & 1;
					D0 >>= 1;
					
					if (D0 == 0) get_next_long_in_D0();

					//roxl #1, D2
					C = D2 >> 31;
					D2 <<= 1;
					D2 |= X;
					X = C;

				} while (--count>-1);

				//0062
				*--A2 = D2;
				
			} while ((int)--D3>-1);

			goto i90;
i6A:
			D1 = 7;
			D4 = 8;
		}
i7E:
		D1 = 8;
		D3 = D2 + 2;
i86:
		get_next_D1_bits_in_D2();

		//0088
		do
		{
			const unsigned char tmp = *(A2 + D2 - 1);
			*--A2 = tmp;
		} while ((int)--D3>-1);
i90:;
	} while (A2 >= A1);

	//0094
	RLE(A1,A4, unpacked_size);
	return;

iA8:
	D1 = 2;
	get_next_D1_bits_in_D2();
	if (D2 < 2) goto i7E;
	if (D2 == 3) goto i6A;
	
	D1 = 8;
	get_next_D1_bits_in_D2();
	D3 = D2 + 4;
	D1 = 8;
	
	goto i86;
}

//c4-cd
//" TETRAGON "

//this is RLE, with 0x6A followed by run count, or 0 for a naked 0x6A
//A0 - dest address
//A1 - source address
//A2 - end of source address
static void RLE(unsigned char *src, unsigned char *dst, unsigned int length)
{
	//unsigned char *dst/*A0*/ = 0x3e742;//this number is plugged in
	//unsigned char *end/*A2*/ = 0x636F8;//this number is plugged in
	unsigned char *end = dst + length;

	//00CE
	do
	{
		unsigned char b = *src++;

		if (b == 0x6A)
		{
			unsigned char count = *src++;
			if (count != 0)
			{
				b = *src++;
				count++;
				do
				{
					*dst++ = b;
				} while (--count);
			}
		}

		*dst++ = b;

	} while (dst < end);

	//00FA
	//goto 0x3e742;//wow!	: this number is plugged in and is the entry point of the unpacked code
}

static void get_next_long_in_D0(void)
{
	//70
	A0 -= 4; D0 = bswap(*(unsigned int *)A0);

	//move #$10,ccr (sets X, clears C)
	//roxr.l #1, D0
	C = X = D0 & 1;
	D0 >>= 1;
	D0 |= 0x80000000;//this bit is a marker, so when it gets shifted out D0 finally hits zero

	char tt[16];
	sprintf_s(tt, 10, "%08X\n", D0);
	OutputDebugStringA(tt);
}

static void get_next_D1_bits_in_D2(void)
{
	//0096
	D1--;
	D2 = 0;
	
	do
	{
		X = C = D0 & 1;
		D0 >>= 1;

		if (D0 == 0) get_next_long_in_D0();

		//roxl #1, D2
		C = D2 >> 31;
		D2 <<= 1;
		D2 |= X;
		X = C;
		
	} while ((int)--D1>-1);
}
