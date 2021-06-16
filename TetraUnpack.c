#include <stdio.h>
#include <stdlib.h>

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
		//fname = "samples/VF-VenloPartyDemo.exe";
		fname = "samples/Tetra_Pack_v2.2.exe";
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
					dump_buffer(b, num_longs * 4);
					disassemble_buffer(b, num_longs * 4);
					unpack(b);
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
static char C;
static char X;
static unsigned char tmp;
static void i70();
static void i96();

static void unpack(unsigned char *src)
{
	A1 = src+0x100;//source data address which starts at 0x100 past start of code
	A4 = 0x3e74a;//it's moved from the LEA of the RLE section.
	A0 = A4;
	A4 += 0x193b0;//source filesize - 256 : this number is plugged in
	
	if (A1 > A4) goto i24;
	A0 = A1;
	A2 += 0x193b0;//filesize - 256, it's added from the A4+= ADDA.L instruction above
	goto i2A;
i24:
	*A4++ = *A1++;
	if (A4 < A0) goto i24;
i2A:
	A1 = 0x44941;//what? : this number is plugged in
	A0 -= 4;
	A2 = *(unsigned int *)A0;
	A1 += (uintptr_t)A1;
	A0 -= 4;
	D0 = *(unsigned int *)A0;
i36:
	D0 >>= 1;
	if (D0 != 0) goto i48;
	i70();
i48:
	if (C) goto iA8;
	D1 = 8;
	D4 = 0;
i4E:
	i96();
	D3 = D2;
	D3 += D4;
i54:
	D1 = 7;
i56:
	D0 >>= 1;
	if (D0 != 0) goto i5C;
	i70();
i5C:
	//roxl #1, D2
	C = D2 >> 31;
	D2 <<= 1;
	D2 |= X;
	X = C;

	if (--D1) goto i56;
	*--A2 = D2;
	if (--D3) goto i54;

	goto i90;
	
i6A:
	D1 = 7;
	D4 = 8;
	goto i4E;

i7E:
	D1 = 8;
	D3 = D2;
	//NOP
	D3 += 2;
i86:
	i96();
	
i88:
	tmp = *(A2 + D2 * 0xffff - 1);
	A2--;
	*A2 = tmp;
	
	if (--D3) goto i88;
i90:
	if (A2 < A1) goto i36;
	goto iCE;

iA8:
	D1 = 2;
	i96();
	if ((D2 & 0xff) < 2) goto i7E;
	if ((D2 & 0xff) == 3) goto i6A;
	D1 = 8;
	i96();
	D3 = D2;
	D3 += 4;
	D1 = 8;
	goto i86;

	//c4-cd
	//" TETRAGON "

	//this is RLE, with 0x6A followed by run count, or 0 for a naked 0x6A
	//A0 - dest address
	//A1 - source address
	//A2 - end of source address
iCE:
	D7 = 0x6A;
	A0 = 0x3e74a;//this number is plugged in
	A2 = 0x636F8;//this number is plugged in
iDC:
	D0 = *A1++;
	if (D0 != D7) goto iF2;
	D1 = 0;
	D1 = *A1++;
	if (D1 == 0) goto iF2;
	D0 = *A1++;
	D1++;
iEC:
	*A0++ = D0;

	D1--;
	if (D1) goto iEC;

iF2:
	*A0++ = D0;
	if (A1 < A2) goto iDC;

	//goto 0x3e742;//wow!	: this number is plugged in and is the entry point of the unpacked code
	return;
	
//i100: data starts here!
}

static void i70(void)
{
	A0 -= 4;
	D0 = *(unsigned int *)A0;

	//move #$10,ccr (sets X, clears C)
	//roxr.l #1, D0
	C = X = D0 & 1;
	D0 >>= 1;
	D0 |= 0x80000000;
}

static void i96(void)
{
	D1--;
	D2 = 0;
i9A:
	D0 >>= 1;
	if (D0 != 0) goto iA0;
	i70();

iA0:
	//roxl #1, D2
	C = D2 >> 31;
	D2 <<= 1;
	D2 |= X;
	X = C;

	D1--;
	if (D1) goto i9A;
}