#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>

#include "dsi.h"

int get_key(const char *name, uint8_t *key, uint32_t len)
{
	char path[256];

	char *home = getenv("HOME");
	if (home == NULL)
	{
		return -1;
	}
	snprintf(path, sizeof(path), "%s/.dsi/%s", home, name);

	FILE *fp = fopen(path, "rb");
	if (fp == 0)
	{
		return -1;
	}

	if (fread(key, len, 1, fp) != 1)
	{
		fclose(fp);
		return -1;
	}
	fclose(fp);

	return 0;
}

int main(int argc, char **argv)
{
	FILE *fjpg;
	unsigned char *buffer;
	unsigned char *tmpbuf;
	unsigned int size;
	int argi;
	struct stat filestats;

	unsigned int mknoteoff = 0x18a;//MakerNote offset
	int update=0;
	int invalid=1;
	dsi_context cryptoctx;
	uint8_t key1[16];
	uint8_t key2[16];
	unsigned char nonce[12];	
	unsigned char cmpmac[16];
	unsigned char calcmac[16];

	if(argc<2)
	{
		printf("twljpgmac_gen v1.0\n");
		printf("Verify/update the MakerNote AES-CCM MAC in twl jpegs.\n");
		printf("Usage:\ntwljpgmac_gen <input.jpg> <options>\n");
		printf("Options:\n");
		printf("-u Update the MAC in the jpg if it's not valid.\n");
		return 0;
	}

	for(argi=2; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "-u", 2)==0)update=1;
	}

	memset(key1, 0, 16);
	memset(key2, 0, 16);
	if(get_key("jpgccm_key1", key1, 16)<0)
	{
		printf("Failed to open jpgccm_key1.\n");
		return 1;
	}
	if(get_key("jpgccm_key2", key2, 16)<0)
	{
		printf("Failed to open jpgccm_key2.\n");
		return 1;
	}

	fjpg = fopen(argv[1], "rb");
	if(fjpg==NULL)
	{
		printf("Failed to open %s\n", argv[1]);
		return 1;
	}
	stat(argv[1], &filestats);
	size = filestats.st_size;
	
	buffer = (unsigned char*)malloc(size);
	tmpbuf = (unsigned char*)malloc(size);
	if(buffer==NULL)
	{
		printf("mem alloc fail\n");
		fclose(fjpg);
		return 2;
	}
	memset(buffer, 0, size);
	memset(tmpbuf, 0, size);
	fread(buffer, 1, size, fjpg);
	fclose(fjpg);

	if(strncmp((char*)&buffer[0x86], "Nintendo", 8))
	{
		printf("not a ninty jpg.\n");
		free(buffer);
		free(tmpbuf);
		return 1;
	}

	if(strncmp((char*)&buffer[0x90], "NintendoDS", 10))
	{
		printf("not a dsi jpg.\n");
		if(strncmp((char*)&buffer[0x90], "Nintendo 3DS", 12)==0)printf("3ds jpg aren't supported.\n");
		free(buffer);
		free(tmpbuf);
		return 1;
	}

	memset(calcmac, 0, 16);
	memcpy(nonce, &buffer[mknoteoff], 12);
	memcpy(cmpmac, &buffer[mknoteoff+12], 16);
	memset(&buffer[mknoteoff], 0, 28);

	dsi_init_ccm(&cryptoctx, key1, 16, 0, size, nonce);
	dsi_encrypt_ccm_macgencmd9(&cryptoctx, buffer, tmpbuf, size, calcmac);

	printf("key1: ");
	if(memcmp(calcmac, cmpmac, 16)==0)
	{
		printf("valid mac\n");
		invalid=0;
	}
	else
	{
		printf("invalid mac\n");
	}
	
	if(invalid)//don't need to verify with the second key when verification with the first key succeeded.
	{
		dsi_init_ccm(&cryptoctx, key2, 16, 0, size, nonce);
		dsi_encrypt_ccm_macgencmd9(&cryptoctx, buffer, tmpbuf, size, calcmac);

		printf("key2: ");
		if(memcmp(calcmac, cmpmac, 16)==0)
		{
			printf("valid mac\n");
			invalid=0;
		}
		else
		{
			printf("invalid mac\n");
		}
	}

	if(invalid && update)
	{
		printf("updating mac since it's invalid.\n");

		FILE *frand = fopen("/dev/random", "rb");
		fread(nonce, 1, 12, frand);
		fclose(frand);

		dsi_init_ccm(&cryptoctx, key2, 16, 0, size, nonce);//use key2 since most DSi jpegs on sdcard/nand use that
		dsi_encrypt_ccm_macgencmd9(&cryptoctx, buffer, tmpbuf, size, calcmac);
		memcpy(&buffer[mknoteoff], nonce, 12);
		memcpy(&buffer[mknoteoff+12], calcmac, 16);

		fjpg = fopen(argv[1], "wb");
		if(fjpg)
		{
			fwrite(buffer, 1, size, fjpg);
			fclose(fjpg);
		}
		else
		{
			printf("failed to open %s for writing\n", argv[1]);
		}
	}

	free(buffer);
	free(tmpbuf);

	return 0;
}

