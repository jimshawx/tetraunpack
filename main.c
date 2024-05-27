#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hunks.h"

extern void *tetraUnpack(unsigned char *source, unsigned int *unpackedlength, unsigned int *unpackAddress);

extern void disassemble_buffer(unsigned char *b, unsigned int len);
extern void dump_buffer(unsigned char *b, unsigned int len);

static int writeExe(void *A4, unsigned int unpacked_size, char *outputname);
static int writeBin(void *A4, unsigned int unpacked_size, char *outputname);

static int readHunks(char *filename, char *outputname);
static int readHunkCode(FILE *f, unsigned int i, char *outputname);
static void readHunkData(FILE *f, unsigned int i);
static void readHunkBss(FILE *f, unsigned int i);
static void readHunkReloc32(FILE *f, unsigned int i);
static void readHunkReloc32Short(FILE *f, unsigned int i);
static void readHunkDebug(FILE* f, unsigned int i);
static void readHunkSymbol(FILE* f, unsigned int i);
static void readHunkUnknown(FILE *f, unsigned int i);

static unsigned int bswap(unsigned int s) { return (s >> 24) | (s << 24) | ((s >> 8) & 0xff00) | ((s << 8) & 0xff0000); }
static void swap(unsigned int *w) { *w = bswap(*w); }
static void swapw(unsigned short *w) { *w = (*w << 8) | (*w >> 8); }

static char verbose = 0;
static char disassemble = 0;
static char dump = 0;
static char binary = 0;
static unsigned int memoryType = 0;

int main(int argc, char **argv)
{
	char *names[2] = { 0 };
	int n_count = 0;
	char optsOK = 1;

	for (int i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
			char opt = argv[i][1];
			if (opt == 'v') verbose = 1;
			else if (opt == 'd') disassemble = 1;
			else if (opt == 'd') dump = 1;
			else if (opt == 'f' && argv[i][2] == 'B') binary = 1;
			else if (opt == 'm' && argv[i][2] == 'F') memoryType = 2;
			else if (opt == 'm' && argv[i][2] == 'C') memoryType = 1;
			else { fprintf(stderr, "unknown option %s\n", argv[i]); optsOK = 0; }
		}
		else
		{
			if (n_count < 2)
				names[n_count] = argv[i];
			n_count++;
		}
	}
	if (n_count != 2) optsOK = 0;

	if (!optsOK)
	{
		fprintf(stdout, "TetraUnpack - unpack TETRAPACKed Amiga executables.\n");
		fprintf(stdout, "Copyright Jim Shaw 2021.  https://bitbucket.org/jimshawx/tetraunpack.\n");
		fprintf(stdout, "This program and its source are in the Public Domain.\n\n");
		fprintf(stdout, "Usage: tetraunpack [-v] [-d] [-b] [-f(B|E)] [-m(C|F)] source destination.\n");
		fprintf(stdout, " v - verbose, show information about the Hunk structure.\n");
		fprintf(stdout, " d - disassemble, produce a disassembly of any HUNK_CODE.\n");
		fprintf(stdout, " b - dump, produce a binary dump of any HUNK_CODE.\n");
		fprintf(stdout, " f - output a B (bin) or E (Hunk executable). Default E.\n");
		fprintf(stdout, " m - for executable output, specify C (MEMF_CHIP) or F (MEMF_FAST) for code hunks in the HUNK_HEADER. Default none.\n");
		return 1;
	}

	return readHunks(names[0], names[1]);
}

static int readHunks(char *filename, char *outputname)
{
	FILE *f;
	if ((f = fopen(filename, "rb")) == (void *)0)
	{
		fprintf(stderr, "can't open %s for reading.\n", filename);
		return 3;
	}

	unsigned int l;

	fread(&l, 1, sizeof l, f);
	swap(&l);
	if (l != HUNK_HEADER)
	{
		fprintf(stderr, "file %s is not an Amiga Hunk file.", filename);
		return 4;
	}

	fseek(f, 0, SEEK_END);
	const long len = ftell(f);
	if (verbose) fprintf(stdout, "file size is %ld\n", len);

	fseek(f, 0, SEEK_SET);

	//HUNK_HEADER

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

	if (verbose) fprintf(stdout, "Hunk count %u, first load %u, last_load %u\n", num_hunks, first_hunk, last_hunk);

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
		if (verbose) fprintf(stdout, "Hunk %u size is %u %08X, flags %08X\n", i, 4 * (l & 0x3fffffff), 4 * (l & 0x3fffffff), flags);
	}

	for (unsigned int i = 0; ; i++)
	{
		unsigned int hunk_type;

		do
		{
			fread(&hunk_type, 1, sizeof hunk_type, f);
			if (feof(f))
				goto file_ended;

			swap(&hunk_type);

			if (verbose) fprintf(stdout, "Hunk %2u: %s", i, getHunkName(hunk_type));

		} while (hunk_type == HUNK_END && !feof(f));

		switch (hunk_type)
		{
			case HUNK_CODE: 
				{
				const int err = readHunkCode(f, i, outputname);
				if (err != 0) return err;
				break;
				}
			case HUNK_DATA: readHunkData(f, i); break;
			case HUNK_BSS: readHunkBss(f, i); break;
			case HUNK_RELOC32: readHunkReloc32(f, i); break;
			case HUNK_ABSRELOC16:
			case HUNK_DREL32:
			case HUNK_RELOC32SHORT: readHunkReloc32Short(f, i); break;
			case HUNK_DEBUG: readHunkDebug(f, i); break;
			case HUNK_SYMBOL: readHunkSymbol(f, i); break;

			case HUNK_UNIT:
			case HUNK_NAME:
			case HUNK_RELOC16:
			case HUNK_RELOC8:
			case HUNK_EXT:
			case HUNK_HEADER:
			case HUNK_OVERLAY:
			case HUNK_BREAK:
			case HUNK_DREL16:
			case HUNK_DREL8:
			case HUNK_LIB:
			case HUNK_INDEX:
			case HUNK_RELRELOC32:
			case HUNK_PPC_CODE:
			case HUNK_RELRELOC26:
			default:
				readHunkUnknown(f, i);
				break;
		}
	}

file_ended:

	fclose(f);

	return 0;
}

static int readHunkCode(FILE *f, unsigned int i, char *outputname)
{
	unsigned int num_longs;
	fread(&num_longs, 1, sizeof num_longs, f);
	swap(&num_longs);

	unsigned char *b;
	unsigned int *c;
	b = c = malloc(num_longs * 4);
	if (c == NULL)
	{
		fprintf(stderr, "out of memory\n");
		return 6;
	}
	
	for (unsigned int j = 0; j < num_longs; j++)
	{
		unsigned int l;
		fread(&l, 1, sizeof l, f);
		*c++ = l;
		swap(&l);
	}
	
	if (dump) dump_buffer(b, num_longs * 4);
	if (disassemble) disassemble_buffer(b, num_longs * 4);

	if (strncmp((char *)b + 0xc4, " TETRAGON ", 10) != 0)
	{
		fprintf(stderr, "CODE Hunk is not TETRAGON packed\n");
		return 0;
	}

	//it's TETRAGON packed, unpack it and write the unpacked data

	unsigned int unpackedSize, unpackAddress;
	void *unpackedData = tetraUnpack(b, &unpackedSize, &unpackAddress);

	if (verbose) fprintf(stdout, "TETRAPACK unpack address: %08X", unpackAddress);
	
	int err = 0;
	if (binary)
		err = writeBin(unpackedData, unpackedSize, outputname);
	else
		err = writeExe(unpackedData, unpackedSize, outputname);

	free(unpackedData);

	return err;
}

static void readHunkData(FILE *f, unsigned int i)
{
	unsigned int num_longs;
	fread(&num_longs, 1, sizeof num_longs, f);
	swap(&num_longs);

	for (unsigned int j = 0; j < num_longs; j++)
	{
		unsigned int l;
		fread(&l, 1, sizeof l, f);
		swap(&l);

		if (j != 0 && j % 8 == 0) fputc('\n', stdout);
		fprintf(stdout, "%04X %04X ", l >> 16, l & 0xffff);
	}
}

static void readHunkBss(FILE *f, unsigned int i)
{
	unsigned int num_longs;
	fread(&num_longs, 1, sizeof num_longs, f);
	swap(&num_longs);
}

static void readHunkReloc32(FILE *f, unsigned int i)
{
	for (;;)
	{
		unsigned int num_offsets;
		fread(&num_offsets, 1, sizeof num_offsets, f);
		swap(&num_offsets);

		if (num_offsets == 0)
			break;

		unsigned int hunk_number;
		fread(&hunk_number, 1, sizeof hunk_number, f);
		swap(&hunk_number);

		if (verbose) fprintf(stdout, "\thunk %u, %u offsets\n", hunk_number, num_offsets);

		for (unsigned int j = 0; j < num_offsets; j++)
		{
			unsigned int offset;
			fread(&offset, 1, sizeof offset, f);
			swap(&offset);
			if (verbose) fprintf(stdout, "\t\t%08X %u\n", offset, offset);
		}
	}
}

static void readHunkReloc32Short(FILE *f, unsigned int i)
{
	for (;;)
	{
		unsigned short num_offsets;
		fread(&num_offsets, 1, sizeof num_offsets, f);
		swapw(&num_offsets);

		if (num_offsets == 0)
			break;

		unsigned short hunk_number;
		fread(&hunk_number, 1, sizeof hunk_number, f);
		swapw(&hunk_number);

		if (verbose) fprintf(stdout, "\thunk %u, %u offsets\n", (unsigned int)hunk_number, (unsigned int)num_offsets);

		for (unsigned int j = 0; j < num_offsets; j++)
		{
			unsigned short offset;
			fread(&offset, 1, sizeof offset, f);
			swapw(&offset);
			if (verbose) fprintf(stdout, "\t\t%08X %u\n", (unsigned int)offset, (unsigned int)offset);
		}
	}
}

static void readDebugHEAD(FILE* f)
{
	char version[8];
	fread(version, 1, 8, f);
	if (verbose) fprintf(stdout, "\t\tHEAD version %.8s\n", version);
	//the rest is unknown
}

static void readDebugHCLN(FILE* f)
{
	if (verbose) fprintf(stdout, "\t\HCLN\n");
}

static void readDebugODEF(FILE* f)
{
	if (verbose) fprintf(stdout, "\t\ODEF\n");
}

static void readDebugUnknown(FILE* f)
{
	if (verbose) fprintf(stdout, "\t\tUnknown debug format\n");
}

static void readDebugLINE(FILE* f, unsigned int baseOffset, unsigned int count)
{
	//filename
	unsigned int len;
	fread(&len, 1, sizeof len, f);
	swap(&len);

	char* name = calloc(len * 4 + 1, 1);
	if (name == NULL)
		return;

	for (unsigned int i = 0; i < len; i++)
		fread(name + i * 4, 1, 4, f);

	if (verbose) fprintf(stdout, "\t\tLINE filename %s\n", name);

	free(name);

	unsigned int line, offset;

	count = ((count-3)-len)/2;

	while (count--)
	{
		fread(&line, 4, 1, f);
		fread(&offset, 4, 1, f);
		swap(&line);
		swap(&offset);
		if (verbose) fprintf(stdout, "%u %u, ", line, baseOffset+offset);
	}
	if (verbose) fprintf(stdout, "\n");
}

static void readHunkDebug(FILE* f, unsigned int i)
{
	unsigned int num_longs;
	fread(&num_longs, 1, sizeof num_longs, f);
	swap(&num_longs);

	long cur = ftell(f);

	unsigned int offset;

	//read the debug information type
	fread(&offset, 1, sizeof offset, f);
	swap(&offset);
	
	char type[4];
	fread(type, 1, 4, f);
	if (verbose) fprintf(stdout, "\thunk %.4s debug type\n", type);
	if (strncmp(type, "HEAD", 4) == 0)
		readDebugHEAD(f);
	else if (strncmp(type, "LINE", 4) == 0)
		readDebugLINE(f, offset, num_longs);
	else if (strncmp(type, "HCLN", 4) == 0)
		readDebugHCLN(f);
	else if (strncmp(type, "ODEF", 4) == 0)
		readDebugODEF(f);
	else
		readDebugUnknown(f);

	fseek(f, cur + (long)num_longs * 4, SEEK_SET);
}

static void readHunkSymbol(FILE* f, unsigned int i)
{
	for (;;)
	{
		//symbol name
		unsigned int len;
		fread(&len, 1, sizeof len, f);
		swap(&len);

		if (len == 0) return;

		char* name = calloc(len * 4 + 1, 1);

		for (unsigned int i = 0; i < len; i++)
			fread(name + i * 4, 1, 4, f);

		unsigned int offset;
		fread(&offset, 4, 1, f);
		swap(&offset);

		if (verbose) fprintf(stdout, "\t\SYMBOL %s@%u\n", name, offset);

		free(name);
	}
}

static void readHunkUnknown(FILE *f, unsigned int i)
{
	//hopefully skip past the unknown hunk

	unsigned int num_longs;
	fread(&num_longs, 1, sizeof num_longs, f);
	swap(&num_longs);

	fseek(f, (long)num_longs * 4, SEEK_CUR);
}

static int writeExe(void *A4, unsigned int unpacked_size, char *outputname)
{
	FILE *f;
	if ((f = fopen(outputname, "wb")) == (void *)0)
	{
		fprintf(stderr, "can't open output file %s\n", outputname);
		return 5;
	}
	
	//write a HUNK_HEADER
	unsigned int tmp;
	tmp = bswap(HUNK_HEADER);
	fwrite(&tmp, 1, sizeof tmp, f);//HUNK_HEADER
	tmp = bswap(0);
	fwrite(&tmp, 1, sizeof tmp, f);//strings
	tmp = bswap(1);
	fwrite(&tmp, 1, sizeof tmp, f);//table size
	tmp = bswap(0);
	fwrite(&tmp, 1, sizeof tmp, f);//first hunk
	tmp = bswap(0);
	fwrite(&tmp, 1, sizeof tmp, f);//last hunk
	tmp = bswap(((unpacked_size + 3) >> 2) + (memoryType << 30));
	fwrite(&tmp, 1, sizeof tmp, f);//hunk sizes

	//write a HUNK_CODE
	tmp = bswap(HUNK_CODE);
	fwrite(&tmp, 1, sizeof tmp, f);
	tmp = bswap((unpacked_size + 3) >> 2);
	fwrite(&tmp, 1, sizeof tmp, f);

	//write the code
	fwrite(A4, 1, unpacked_size, f);
	//write any padding
	tmp = 0;
	fwrite(&tmp, 1, (4 - (unpacked_size & 3)) & 3, f);

	//write a HUNK_END
	tmp = bswap(HUNK_END);
	fwrite(&tmp, 1, sizeof tmp, f);

	fclose(f);
}

static int writeBin(void *A4, unsigned int unpacked_size, char *outputname)
{
	FILE *f;
	if ((f = fopen(outputname, "wb")) == (void *)0)
	{
		fprintf(stderr, "can't open output file %s\n", outputname);
		return 5;
	}

	fwrite(A4, 1, unpacked_size, f);
	fclose(f);
}
