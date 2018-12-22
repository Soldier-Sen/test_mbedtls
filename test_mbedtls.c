#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <getopt.h>

#include <mbedtls/config.h>
#include <mbedtls/aes.h>

#define NO_ARG				0
#define HAS_ARG				1

static struct option long_options[] = {
	{"aes", HAS_ARG, 0, 'a'},
	{"function", HAS_ARG, 0, 'f'},
	{"serialNumber", NO_ARG, 0, 's'},
	{"macAddress", NO_ARG, 0, 'm'},
	{0, 0, 0, 0}
};

static const char *short_options = "Vvf:MmSs";

void usage(void)
{
	int i;

	printf("\mbedtls usage:\n");
	for (i = 0; i < sizeof(long_options) / sizeof(long_options[0]) - 1; i++) 
	{
		if (isalpha(long_options[i].val))
			printf("-%c ", long_options[i].val);
		else
			printf("   ");
		printf("--%s", long_options[i].name);

	}
	printf("\n");
}


#define AES_KEY_LEN  16
// key: 35408382fef5a3decf784f74d3f1d97e
int load_key(const char *keyFile, unsigned char *key, int keyLen);
int load_file_data(const char *fileName, unsigned char **data, int *data_len);
int save_file(const char *path, const unsigned char *data, unsigned int size);

int main(int argc, char *argv[])
{
	int cbc_result = -1;
	unsigned char iv[16] = {0};
	char msg[16+1] = "0123456789abcdef";
	char enc_buf[16+1] = {0};
	char dec_buf[16+1] = {0};
	char fileName[16] = "Makefile";
	
	unsigned char key[AES_KEY_LEN] = {0};
	mbedtls_aes_context ctx;
	char aes_mode[8] = {0};
	
	int ch;
	int option_index = 0;
	opterr = 0;
	while ((ch = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
	{
		switch (ch) 
		{
			case 'f':
				printf("optind = %d, optarg = %s\n", optind, optarg);
				break;
			case 'v':
			//version_flag = 1;
				break;

			case 's':
			//serialNumber_flag = 1;
				break;

			case 'M':
			case 'm':
			//macAddress_flag = 1;
				break;
			case 'a':
				strcpy(aes_mode, optarg);
				printf("aes_mode = %s\n", aes_mode);
			//all_flag = 1;
				break;

			default:
			printf("unknown option found: %c\n", ch);
			return -1;
		}
	}

	
	mbedtls_aes_init(&ctx);

	if(strcmp(aes_mode, "cbc-128") == 0)
	{
		char key_file_128[16] = "aes128.key";
		load_key(key_file_128, key, sizeof(key));
		mbedtls_aes_setkey_enc(&ctx, key, AES_KEY_LEN*8);
		
		int len = sizeof(msg) - 1;
		cbc_result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv, msg, enc_buf);
		//cbc_result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT,msg, enc_buf);
		printf("ENC: cbc_result = %d, msg:[%s] -> dec_buf:[%s]\n",cbc_result, msg, enc_buf);
		
		memset(iv, 0x0, sizeof(iv));
		mbedtls_aes_setkey_dec(&ctx, key, AES_KEY_LEN*8);
		cbc_result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv, enc_buf, dec_buf);
		//cbc_result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT,msg, enc_buf);
		printf("DEC: cbc_result = %d, [%s] -> dec = [%s]\n",cbc_result, enc_buf, dec_buf);

	}

	
	mbedtls_aes_free( &ctx );
    return 0;
}

int load_key(const char *keyFile, unsigned char *key, int keyLen)
{
	int ret = -1;
	FILE *fp = fopen(keyFile, "rb");
	if(!fp)
	{
		perror("open key file");
		return -1;
	}
	ret = fread(key, 1, keyLen, fp);
	for(int i = 0; i < keyLen; i++)
	{
		printf("%02x", key[i]);
	}
	printf("\n");
	fclose(fp);
	return ret;
}

int load_file_data(const char *fileName, unsigned char **data, int *data_len)
{
	int ret = -1;
	FILE *fp = fopen(fileName, "rb");
	if(!fp)
	{
		perror("open file");
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	*data_len = ftell(fp);
	rewind(fp);

	*data = (unsigned char *)malloc(*data_len);
	if(*data)
		ret = fread(*data, 1, *data_len, fp);
	fclose(fp);
	return ret;
}
int save_file(const char *path, const unsigned char *data, unsigned int size)
{
	int ret = 0;

	if(path == NULL){
		printf("%s, %d  --path is null\n", __func__, __LINE__);
		return -1;
	}
	//printf("====[%s: %s],size=%d ====\n\n",__func__, path, size);
	FILE *fp = fopen(path, "wb");
	if(fp == NULL) {
		perror("====open file===\n");
		return -1;
	}
	ret = fwrite(data, 1, size, fp);
	fclose(fp);
	return ret;	
}
