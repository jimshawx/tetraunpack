#define HUNK_UNIT	0x3E7
#define HUNK_NAME		0x3E8
#define HUNK_CODE		0x3E9
#define HUNK_DATA		0x3EA
#define HUNK_BSS		0x3EB
#define HUNK_RELOC32		0x3EC
#define HUNK_RELOC16		0x3ED
#define HUNK_RELOC8		0x3EE
#define HUNK_EXT		0x3EF
#define HUNK_SYMBOL		0x3F0
#define HUNK_DEBUG		0x3F1
#define HUNK_END		0x3F2
#define HUNK_HEADER		0x3F3
#define HUNK_OVERLAY		0x3F5
#define HUNK_BREAK		0x3F6
#define HUNK_DREL32		0x3F7
#define HUNK_DREL16		0x3F8
#define HUNK_DREL8		0x3F9
#define HUNK_LIB		0x3FA
#define HUNK_INDEX		0x3FB
#define HUNK_RELOC32SHORT	0x3FC
#define HUNK_RELRELOC32		0x3FD
#define HUNK_ABSRELOC16		0x3FE
#define HUNK_PPC_CODE  	0x4E9
#define HUNK_RELRELOC26  	0x4EC

static struct
{
	const char *const name;
	unsigned int value;
} hunk_names[] = {
	{"HUNK_UNIT", 0x3E7},
	{"HUNK_NAME", 0x3E8},
	{"HUNK_CODE", 0x3E9},
	{"HUNK_DATA", 0x3EA},
	{"HUNK_BSS", 0x3EB},
	{"HUNK_RELOC32", 0x3EC},
	{"HUNK_RELOC16", 0x3ED},
	{"HUNK_RELOC8", 0x3EE},
	{"HUNK_EXT", 0x3EF},
	{"HUNK_SYMBOL", 0x3F0},
	{"HUNK_DEBUG", 0x3F1},
	{"HUNK_END", 0x3F2},
	{"HUNK_HEADER", 0x3F3},
	{"HUNK_OVERLAY", 0x3F5},
	{"HUNK_BREAK", 0x3F6},
	{"HUNK_DREL32", 0x3F7},
	{"HUNK_DREL16", 0x3F8},
	{"HUNK_DREL8", 0x3F9},
	{"HUNK_LIB", 0x3FA},
	{"HUNK_INDEX", 0x3FB},
	{"HUNK_RELOC32SHORT", 0x3FC},
	{"HUNK_RELRELOC32", 0x3FD},
	{"HUNK_ABSRELOC16", 0x3FE},
	{"HUNK_PPC_CODE", 0x4E9},
	{"HUNK_RELRELOC26", 0x4EC},
};

static const char *getHunkName(unsigned int hunkType)
{
	for (unsigned int i= 0; i < sizeof hunk_names / sizeof *hunk_names; i++)
	{
		if (hunk_names[i].value == hunkType)
			return hunk_names[i].name;
	}
	return "HUNK_unknown";
}
