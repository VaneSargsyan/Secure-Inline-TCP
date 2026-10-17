#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(void){

	EVP_PKEY_CTX  *ctx = NULL;
	EVP_PKEY_CTX  *derive_ctx = NULL;
	EVP_PKEY  *device1 = NULL;
	EVP_PKEY   *device2 = NULL;

	
	unsigned  char secret1[32], secret2[32];
	size_t length1 = sizeof(secret1);
	size_t length2 = sizeof(secret2);

	
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
	
	if(!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &device1)<= 0 || EVP_PKEY_keygen(ctx, &device2)<= 0){
		goto error;
}


	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;

	derive_ctx = EVP_PKEY_CTX_new(device1, NULL);
	
	if(!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0 || EVP_PKEY_derive_set_peer(derive_ctx, device2) <= 0 || EVP_PKEY_derive(derive_ctx, secret1, &length1)<= 0){

	goto error;
}

	EVP_PKEY_CTX_free(derive_ctx);
	derive_ctx = EVP_PKEY_CTX_new(device2, NULL);

	if(!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0 ||
		EVP_PKEY_derive_set_peer(derive_ctx, device1)<=0 ||
		EVP_PKEY_derive(derive_ctx, secret2, &length2) <= 0){
		goto error;
}

if(length1 != length2 || CRYPTO_memcmp(secret1, secret2, length1) != 0){
	goto error;
}

printf("Device1 and Device2 derived the same secret\n");


OPENSSL_cleanse(secret1, sizeof(secret1));
OPENSSL_cleanse(secret2, sizeof(secret2));
EVP_PKEY_CTX_free(derive_ctx);
EVP_PKEY_free(device1);
EVP_PKEY_free(device2);
return 0;

error:
	fprintf(stderr, "Diffie-Hellman test failed\n");
	ERR_print_errors_fp(stderr);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_CTX_free(derive_ctx);
	EVP_PKEY_free(device1);
	EVP_PKEY_free(device2);
	OPENSSL_cleanse(secret1, sizeof(secret1));
	OPENSSL_cleanse(secret2, sizeof(secret2));
	return 1;
}
