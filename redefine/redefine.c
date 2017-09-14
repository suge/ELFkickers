/* redefine: Copyright (C) 2017,2017 by k1988 <zhaohaiyang.1988@gmail.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <elf.h>
#include "elfrw.h"

#ifndef TRUE
#define	TRUE	1
#define	FALSE	0
#endif

 /* The memory-allocation macro.
  */
#define alloc(p, n) \
    (((p) = realloc(p, n)) || (fputs("Out of memory.\n", stderr), exit(1), 0))

  /* The online help text.
   */
static char const *yowzitch =
"Usage: redefine [OPTIONS] FILE [SYMBOL...]\n"
"Change the name of dynamic symbols in an ELF object file.\n\n"
"  -n, --name=ORGNAME    the part name to be replace.\n"
"  -p, --replace_name=NEWNAME the new part name.\n"
"  -i, --verbose         Describe some debug information.\n"
"      --help            Display this help and exit.\n"
"      --version         Display version information and exit.\n\n";

/* The version text.
 */
static char const *vourzhon =
"redefine: version 1.0\n"
"Copyright (C) 2017,2017 by k1988 <zhaohaiyang.1988@gmail.com>\n"
"License GPLv2+: GNU GPL version 2 or later.\n"
"This is free software; you are free to change and redistribute it.\n"
"There is NO WARRANTY, to the extent permitted by law.\n";

static int		verbose;	/* whether to tell the user */

static char	      *seek_name_part = 0;	/* the list of symbol names to seek */
static char	      *replace_name_part = 0;	/* the list of symbol names to replace to */

static char const      *theprogram;	/* the name of this executable */
static char const      *thefilename;	/* the current file name */
static FILE	       *thefile;	/* the current file handle */

static Elf64_Ehdr	ehdr;		/* the file's ELF header */

/* An error-handling function. The given error message is used only
 * when errno is not set.
 */
static int err(char const *errmsg)
{
	fprintf(stderr, "%s: %s: %s\n", theprogram, thefilename,
		errno ? strerror(errno) : errmsg);
	return FALSE;
}

/* An error-handling function specifically for errors in the
 * command-line syntax.
 */
static int badcmdline(char const *errmsg)
{
	fprintf(stderr, "%s: %s\nTry --help for more information.\n",
		theprogram, errmsg);
	exit(EXIT_FAILURE);
}

/* readheader() checks to make sure that this is in fact a proper ELF
 * object file that we're proposing to munge.
 */
static int readheader(void)
{
	if (elfrw_read_Ehdr(thefile, &ehdr) != 1)
	{
		if (ferror(thefile))
			return err("not an ELF file.");
		fprintf(stderr, "%s: unrecognized ELF file type.\n", thefilename);
		return FALSE;
	}
	if (!ehdr.e_shoff)
		return err("no section header table.");
	if (ehdr.e_shentsize != sizeof(Elf32_Shdr) &&
		ehdr.e_shentsize != sizeof(Elf64_Shdr))
		return err("unrecognized section header size");

	return TRUE;
}

/* changestrtabs() finds all target function name in a given string table that
 * appear in the seek_name_part and alters their to custom function name.
 */
static int changestrtabs(char* strtab, int count)
{
	int n = 0;
	char* dest = strtab;
	char* repalce_start = 0;
	int replace_name_part_len = 0;
	int symbol_len = 0;
	int char_count_after_seek = 0;
	for (; dest - strtab < count - 1; )
	{
		if (*dest == 0)
		{
			dest++;
			continue;
		}

		repalce_start = strstr(dest, seek_name_part);
        symbol_len = strlen(dest);
		if (repalce_start != 0)
		{
			if (verbose)
				printf("symbol \"%s\" need alter.\n", dest);
			replace_name_part_len = strlen(replace_name_part);
			memcpy(repalce_start, replace_name_part, replace_name_part_len);
			if (replace_name_part_len < strlen(seek_name_part))
			{
			    char_count_after_seek = symbol_len - (repalce_start - dest) - strlen(seek_name_part);
			    // move left chars
			    memcpy(repalce_start + replace_name_part_len, repalce_start + strlen(seek_name_part), char_count_after_seek);

				// paddirng zero bytes
				memset(repalce_start + replace_name_part_len + char_count_after_seek, 0, strlen(seek_name_part) - replace_name_part_len);
			}

			if (verbose)
				printf("new symbol \"%s\".\n", dest);


			dest += symbol_len;
			n++;
		}
		else
		{
			dest += symbol_len;
		}
	}
	return n;
}

// 根据符号表信息重新生成.hash区域内容。注意的是symtab中不包含elf第一个空符号，仅包括有效符号
// strtab是elf中原始文件内容，count是symtab中包含的符号个数
static int rehash(Elf64_Shdr *shdrs, Elf64_Sym *symtab, const char* strtab, int count)
{
	// hash区起始内存
	Elf32_Word		    *chain = malloc(1024);

	// 计算出来的hash桶数
	Elf32_Word			bucketnum;

	// 计算出来的hash临时变量
	Elf32_Word			hash;

	// 循环中指定当前符号名称
	unsigned char const	       *name;

	// 循环中指定当前符号
	Elf64_Sym  *sym;

	// 计算hash的临时变量
	Elf32_Sword			n;

	Elf32_Word		    *modify_chain;
	int hash_size;


	int i,j,k = 0;
	for (i = 0; i < ehdr.e_shnum; ++i)
	{
		if (shdrs[i].sh_type != SHT_HASH) continue;

		if (verbose) printf("\nfound .hash section: \n\t address: %llx\n\t file offset: %llx\n\t size: %llx\n\t link: %x\n\t addralign: %llx\n\t section entry size: %llx\n\n", shdrs[i].sh_addr, shdrs[i].sh_offset, shdrs[i].sh_size, shdrs[i].sh_link, shdrs[i].sh_addralign, shdrs[i].sh_entsize);

		// 申请2倍大的空间
		hash_size = shdrs[i].sh_size;
		modify_chain = chain = malloc(hash_size * 2);
		if (fseek(thefile, shdrs[i].sh_offset, SEEK_SET) ||
			fread(chain, shdrs[i].sh_size, 1, thefile) != 1)
			return err("invalid hash table");

		// use orignal bucket num
        bucketnum = modify_chain[0];
		// use new sym count
		modify_chain[1] = count + 1;

		chain += 2 + bucketnum; // jump to chain list
		memset(modify_chain + 2, 0, shdrs[i].sh_size * 2 - 2 * sizeof(chain[0]));// empty bukkets and chains

		// 我要修改的这个android arm架构的so文件中，
		// 符号表是倒着计算hash值的（不确定其它平台或其它编译器生成的顺序）
		for (j = count - 1; j >= 0; --j, ++sym)
		{
			sym = symtab + j;
			name = strtab + sym->st_name;
			printf("sym %d %s \n", j, name);
			for (hash = 0; *name; ++name)
			{
				hash = (hash << 4) + *name;
				hash = (hash ^ ((hash & 0xF0000000) >> 24)) & 0x0FFFFFFF;
			}
			hash = hash % bucketnum;
			n = hash - bucketnum;//< this step n is negtive, so n is a bukket index,but chain[n] is chain index
			while (chain[n])
				n = chain[n];
			chain[n] = j + 1;
		}

		// HEX格式输出修改后的hash表
		if (verbose) printf("\nmodifyed hash table(%d,%d) \n", *modify_chain,modify_chain[1]);
		k = 0;
		for (; k < hash_size / sizeof(Elf32_Word); k += 1) {
			if (!(k % 4))
			{
				if (verbose) printf("0x");
			}
			if (verbose) printf("%08x ", *(modify_chain + k));
			if ((k % 4) == 3)
			{
				if (verbose) printf("\n");
			}
		}

		// write back the hash section
		if (fseek(thefile, shdrs[i].sh_offset, SEEK_SET) || fwrite(modify_chain, shdrs[i].sh_size, 1, thefile) != 1) return err("write hash table failed");
		break;
	}
	return 0;
}

/* redefine() does the grunt work of locating the symbol tables.
 */
static int redefine(void)
{
	Elf64_Shdr *shdrs = NULL;
	Elf64_Sym *symtab = NULL;
	char *strtab = NULL;
	unsigned long offset;
	int count;
	int changed;
	int i, n;

	if (!readheader())
		return FALSE;
	changed = FALSE;
	alloc(shdrs, ehdr.e_shnum * sizeof *shdrs);
	if (fseek(thefile, ehdr.e_shoff, SEEK_SET) ||
		elfrw_read_Shdrs(thefile, shdrs, ehdr.e_shnum) != ehdr.e_shnum)
		return err("invalid section header table.");
	for (i = 0; i < ehdr.e_shnum; ++i)
	{
		if (shdrs[i].sh_type != SHT_SYMTAB && shdrs[i].sh_type != SHT_DYNSYM)
			continue;

		if (shdrs[i].sh_entsize != sizeof(Elf32_Sym) &&
			shdrs[i].sh_entsize != sizeof(Elf64_Sym))
		{
			err("symbol table of unrecognized structure ignored.");
			continue;
		}
		offset = shdrs[i].sh_offset + shdrs[i].sh_info * shdrs[i].sh_entsize;
		count = shdrs[i].sh_size / shdrs[i].sh_entsize - shdrs[i].sh_info;
		if (!count)
			continue;
		n = shdrs[shdrs[i].sh_link].sh_size;
		alloc(symtab, count * sizeof *symtab);
		alloc(strtab, n);
		if (fseek(thefile, offset, SEEK_SET) ||
			elfrw_read_Syms(thefile, symtab, count) != count)
			return err("invalid symbol table");
		if (fseek(thefile, shdrs[shdrs[i].sh_link].sh_offset, SEEK_SET) ||
			fread(strtab, n, 1, thefile) != 1)
			return err("invalid associated string table");

		if (verbose) printf("try changestrtabs!!!!!! \n");
		if (changestrtabs(strtab, n))
		{
			changed = TRUE;
			if (fseek(thefile, shdrs[shdrs[i].sh_link].sh_offset, SEEK_SET) || fwrite(strtab, n, 1, thefile) != 1) return err("invalid write string table");
		}
		break;
	}

	if (changed)
	{
		rehash(shdrs, symtab, strtab, count);
	}

	if (verbose && !changed)
		printf("%s: nothing changed.\n", thefilename);
	free(strtab);
	free(symtab);
	free(shdrs);
	return TRUE;
}

/* readoptions() parses the command-line arguments. It only returns if
 * the syntax is valid and there is work to do.
 */
static void readcmdline(int argc, char *argv[])
{
	static char const *optstring = "n:ip:";
	static struct option const options[] = {
	{ "name", required_argument, 0, 'n' },
	{ "replace_name", required_argument, 0, 'p' },
	{ "verbose", no_argument, 0, 'i' },
	{ "help", no_argument, 0, 'H' },
	{ "version", no_argument, 0, 'V' },
	{ 0, 0, 0, 0 }
	};

	int n;

	if (argc == 1)
	{
		fputs(yowzitch, stdout);
		exit(EXIT_SUCCESS);
	}

	theprogram = argv[0];
	while ((n = getopt_long(argc, argv, optstring, options, NULL)) != EOF)
	{
		switch (n)
		{
		case 'n':
			n = strlen(optarg) + 1;
			alloc(seek_name_part, n);
			memcpy(seek_name_part, optarg, n);
			break;
		case 'p':
			n = strlen(optarg) + 1;
			alloc(replace_name_part, n);
			memcpy(replace_name_part, optarg, n);
			break;
		case 'i':
			verbose = TRUE;
			break;
		case 'H':
			fputs(yowzitch, stdout);
			exit(EXIT_SUCCESS);
		case 'V':
			fputs(vourzhon, stdout);
			exit(EXIT_SUCCESS);
		}
	}
	if (optind == argc)
		badcmdline("no input files");
	if (!seek_name_part && !replace_name_part)
		badcmdline("nothing to do");

	if (strlen(replace_name_part) > strlen(seek_name_part))
		badcmdline("not support redefine a longer name");

	thefilename = argv[optind];
	++optind;
}

/* main() builds the array of symbol names, opens the object file, and
 * calls redefine().
 */
int main(int argc, char *argv[])
{
	int r;

	readcmdline(argc, argv);

	if (!(thefile = fopen(thefilename, "rb+")))
	{
		err("unable to open.");
		return EXIT_FAILURE;
	}

	r = redefine();

	fclose(thefile);
	if (!r){
	    printf("som error happened!\n");
	}
	getchar();
	return r ? EXIT_SUCCESS : EXIT_FAILURE;
}
