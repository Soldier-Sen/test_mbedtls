#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>

#include <mbedtls/config.h>
#include <mbedtls/aes.h>

#define AES_KEY_LEN  16
// key: 35408382fef5a3decf784f74d3f1d97e
int load_key(const char *keyFile, unsigned char *key, int keyLen);
int load_file_data(const char *fileName, unsigned char **data, int *data_len);
int save_file(const char *path, const unsigned char *data, unsigned int size);

int main(int argc, char *argv[])
{
	char *key_file = "aes.key";
	unsigned char iv[16] = {0};
	char msg[16] = "hello ipcam";
	char enc_buf[16+1] = {0};
	char dec_buf[16+1] = {0};

	char fileName[16] = "Makefile";
	
	unsigned char key[AES_KEY_LEN] = {0};
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);

	load_key(key_file, key, sizeof(key));
	mbedtls_aes_setkey_enc(&ctx, key, sizeof(key)*8);

	int len = sizeof(msg);
	int cbc_result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv, msg, enc_buf);
	printf("ENC: cbc_result = %d, msg:[%s] -> dec_buf:[%s]\n",cbc_result, msg, enc_buf);

	cbc_result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv, enc_buf, dec_buf);
	printf("DEC: cbc_result = %d, [%s] -> dec = %s\n",cbc_result, enc_buf, dec_buf);
	//printf("ENC: cbc_result = %d\n",cbc_result);
	
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