#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/time.h>
#include <ctype.h>
#include <getopt.h>

#include <mbedtls/config.h>
#include <mbedtls/aes.h>
#include <mbedtls/md5.h>


#define NO_ARG				0
#define HAS_ARG				1

static struct option long_options[] = {
	{"mode", HAS_ARG, 0, 'm'},
	{"file", HAS_ARG, 0, 'f'},
	{"string", HAS_ARG, 0, 's'},
	{0, 0, 0, 0}
};

static const char *short_options = "f:m:s:";

void usage(void)
{
	int i;

	printf("\nmbedtls usage:\n");
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


#define AES_128_KEY_LEN  16
#define AES_256_KEY_LEN  32

// key: 35408382fef5a3decf784f74d3f1d97e
int load_key(const char *keyFile, unsigned char *key, int keyLen);
int load_file_data(const char *fileName, unsigned char **data, int *data_len);
int save_file(const char *path, const unsigned char *data, unsigned int size);

int main(int argc, char *argv[])
{
	int result = -1;
	unsigned char iv[16] = {0};
	//char msg[16+1] = "0123456789abcd";
	char msg[16+1] = {0};
	char buf[4096] = {0};
	char enc_buf[16+1] = {0};
	char dec_buf[16+1] = {0};
	char fileName[64] = "";
	struct timeval start, end;
	
	mbedtls_aes_context ctx;
	char mode[8] = {0};
	
	int ch;
	int option_index = 0;
	opterr = 0;
	while ((ch = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
	{
		switch (ch) 
		{
			case 'f':
				strncpy(fileName, optarg, sizeof(fileName) - 1);
				printf("optind = %d, optarg = %s, fileName = %s\n", optind, optarg, fileName);
				break;
			case 's':
				strncpy(msg, optarg, sizeof(msg) - 1);
				break;
			case 'm':
				strcpy(mode, optarg);
				printf("mode = %s\n", mode);
			//all_flag = 1;
				break;

			default:
			printf("unknown option found: %c\n", ch);
			return -1;
		}
	}

	mbedtls_aes_init(&ctx);

	if(strcmp(mode, "cbc-128") == 0)
	{
		unsigned char key[AES_128_KEY_LEN] = {0};
		char key_file_128[16] = "aes128.key";
		load_key(key_file_128, key, sizeof(key));
		mbedtls_aes_setkey_enc(&ctx, key, AES_128_KEY_LEN*8);
		
		int len = sizeof(msg) - 1;
		result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv, msg, enc_buf);
		//result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT,msg, enc_buf);
		printf("ENC: cbc_result = %d, 明文msg:[%s] -> 密文dec_buf:[%s]\n",result, msg, enc_buf);
		
		memset(iv, 0x0, sizeof(iv));
		mbedtls_aes_setkey_dec(&ctx, key, AES_128_KEY_LEN*8);
		result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv, enc_buf, dec_buf);
		//result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT,msg, enc_buf);
		printf("DEC: cbc_result = %d, [%s] -> dec = [%s]\n",result, enc_buf, dec_buf);

	}
	else if(strcmp(mode, "cbc-256") == 0)
	{
		unsigned char key[AES_256_KEY_LEN] = {0};
		char key_file_256[16] = "aes256.key";
		load_key(key_file_256, key, sizeof(key));
		mbedtls_aes_setkey_enc(&ctx, key, AES_256_KEY_LEN*8);
		
		int len = sizeof(msg) - 1;
		result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv, msg, enc_buf);
		//result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT,msg, enc_buf);
		printf("ENC: cbc_result = %d, 明文msg:[%s] -> 密文dec_buf:[%s]\n",result, msg, enc_buf);
		
		memset(iv, 0x0, sizeof(iv));
		mbedtls_aes_setkey_dec(&ctx, key, AES_256_KEY_LEN*8);
		result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv, enc_buf, dec_buf);
		//result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT,msg, enc_buf);
		printf("DEC: 256 cbc_result = %d, [%s] -> dec = [%s]\n",result, enc_buf, dec_buf);
	}
	else if(strcmp(mode, "ecb") == 0)
	{
		//密钥长度可以选择256
		unsigned char key[AES_128_KEY_LEN] = {0};
		char key_file_128[16] = "aes128.key";
		load_key(key_file_128, key, sizeof(key));
		//加密
		mbedtls_aes_setkey_enc(&ctx, key, AES_128_KEY_LEN*8);
		result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, msg, enc_buf);
		printf("ENC: ecb result = %d, 明文msg:[%s] -> 密文dec_buf:[%s]\n",result, msg, enc_buf);
		//解密
		mbedtls_aes_setkey_dec(&ctx, key, AES_128_KEY_LEN*8);
		result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, enc_buf, dec_buf);
		printf("DEC: ecb result = %d, [%s] -> dec = [%s]\n",result, enc_buf, dec_buf);
	}
	else if(strcmp(mode, "md5") == 0)
	{
		unsigned char digest[16] = {0};
		mbedtls_md5_context md5_ctx;

		//求文件的MD5 值
		if(strlen(fileName) > 0)
		{
			int read_len = 0;
			FILE *fp = fopen(fileName, "rb");
			if(!fp){printf("fopen %s fail !", fileName);return -1;}

			gettimeofday(&start, NULL);
			mbedtls_md5_init(&md5_ctx);
			mbedtls_md5_starts_ret(&md5_ctx);
			while((read_len = fread(buf, 1, sizeof(buf), fp)) > 0){
				//printf("read_len = %d\n", read_len);
				mbedtls_md5_update_ret(&md5_ctx, buf, read_len);
			}
			mbedtls_md5_finish_ret(&md5_ctx, digest);
			gettimeofday(&end, NULL);
			fclose(fp);
			mbedtls_md5_free(&md5_ctx);
			float use_time = (end.tv_sec - start.tv_sec)*1000 + (end.tv_usec -start.tv_usec)/1000.0;
			printf("file %s use time: %.4f ms, digest:", fileName, use_time);
			for(int i = 0; i< sizeof(digest); i++)
			{
				 printf("%02x", digest[i]);
			}
			printf("\n");
		}
		//求指定字符串的MD5 值
		if(strlen(msg) > 0)
		{
			mbedtls_md5_init(&md5_ctx);
			mbedtls_md5_starts_ret(&md5_ctx);

			mbedtls_md5_update_ret(&md5_ctx, msg, strlen(msg));
			mbedtls_md5_finish_ret(&md5_ctx, digest);
			mbedtls_md5_free(&md5_ctx);
			printf("string %s digest:", msg);
			for(int i = 0; i< sizeof(digest); i++)
			{
				 printf("%02x", digest[i]);
			}
			printf("\n");
		}
		
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
