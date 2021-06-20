#include <stdlib.h>

static void get_next_long_in_D0(void);
static void get_next_D1_bits_in_D2(void);
static void RLE(unsigned char *src, unsigned char *dst, unsigned int length);
static unsigned int bswap(unsigned int s) { return (s >> 24) | (s << 24) | ((s >> 8) & 0xff00) | ((s << 8) & 0xff0000); }

static unsigned char *A0, *A1, *A2, *A4;
static unsigned int D0, D1, D2, D3, D4;
static unsigned char C, X;

//
// tetraUnpack
//
// source - pointer to the packed code
// unpackedLength - the size of the unpacked code is written here
// unpackAddress - the original unpack address
// return - a buffer containing the unpacked code (you need to free() this buffer)
//
void *tetraUnpack(unsigned char *source, unsigned int *unpackedlength, unsigned int *unpackAddress)
{
	A1 = source + 0x100;//source data address which starts at 0x100 past start of unpacker code

	//pull out the parameters for the unpacker
	const unsigned int magic_packed_size = bswap(*(unsigned int *)(source + 0x14));
	const unsigned int magic_unpack_address = bswap(*(unsigned int *)(source + 0xfc));
	const unsigned int magic_stage1_unpack_address = bswap(*(unsigned int *)(source + 0x2c));
	
	A4 = magic_unpack_address;//unpack target address it's moved from the LEA of the RLE section.
	*unpackAddress = magic_unpack_address;
	
	//A1 - source address
	//A4 - unpack address

	//overlap check to make sure not unpacking over the packed data
	//(don't need to worry about this as we're unpacking to a separate buffer entirely)
	
	//is source address <= unpack address
	//if (A1 <= A4)
	{
		A0 = A1 + magic_packed_size;//filesize - 256, it's added from the A4+= ADDA.L instruction above
		//A0 is the end of the packed source data
	}
	//else
	//{
	//A0 = A4 + magic_packed_size;//source filesize - 256, i.e. size of compressed data following the unpacker : this number is plugged in
	//A0 - unpack address + packed size
	//source address >= unpack address
	//copy from source area to unpack area, until unpack address = unpack address + packed size
	//	do
	//	{
	//		*A1++ = *A4++;
	//	} while (A4 < A0);
	//result of this loop:
	//	A4 == A0
	//	A4 = unpack address + packed size
	//don't care:
	//	A1 += A0-A4
	//	A1 = source address + (unpack address + packed size) - unpack address
	//     = source address + packed size
	//}
	
	A1 = magic_stage1_unpack_address;//this number is plugged in

	//A0 is pointing at end of packed data
	
	A0 -= 4; A2 = bswap(*(unsigned int *)A0);//this number + magic_stage1_unpack_address = end of unpack area
	A2 += (uintptr_t)A1;//A2 is end of unpack area
	A0 -= 4; D0 = bswap(*(unsigned int *)A0);

	//A0 is pointing at end of packed data
	//A1 is pointing at the beginning of the unpack location for 1st step of compression
	//A2 is pointing at end of unpack location
	//A4 is pointing at start of unpack location

	//fix the above pointers to point into an unpack buffer of our own
	const unsigned int unpacked_size = A2 - A4;
	const unsigned int unpacked_step1_size = A1 - A4;
	A4 = calloc(1,unpacked_size);
	if (A4 == NULL)
		return ((void *)0);
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
	} while (A2 > A1);

	//0094
	RLE(A1,A4, unpacked_size);
	*unpackedlength = unpacked_size;
	
	return A4;

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
	//unsigned char *dst /*A0*/
	//unsigned char *end /*A2*/ 
	unsigned char *end = dst + length;

	//00CE
	do
	{
		unsigned char b = *src++;

		if (b == 0x6A)
		{
			int count = *src++;
			if (count != 0)
			{
				b = *src++;
				count++;
				do
				{
					*dst++ = b;
				} while (--count>=0);
			}
		}

		*dst++ = b;

	} while (dst < end);

	//00FA
	//goto 0x3e742;
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
