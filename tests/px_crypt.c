#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <string.h>

#include "px_crypt.h"

int main(void) {
	unsigned char plain[512], encrypted[512], decrypted[512];
	char long_password[257];
	int i;

	assert(px_passwd_checksum(NULL) == 0);
	assert(px_passwd_checksum("") == 0);

	/* Checksum inputs are deterministic and distinct. */
	assert(px_passwd_checksum("a") != 0);
	assert(px_passwd_checksum("a") == px_passwd_checksum("a"));
	assert(px_passwd_checksum("password") != px_passwd_checksum("different"));

	memset(long_password, 'x', sizeof(long_password) - 1);
	long_password[sizeof(long_password) - 1] = '\0';
	assert(px_passwd_checksum(long_password) == px_passwd_checksum(
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));

	for(i = 0; i < (int)sizeof(plain); i++)
		plain[i] = (unsigned char)(i * 37 + 11);

	px_encrypt_db_block(plain, encrypted, 0x1234, sizeof(plain), 7);
	assert(memcmp(plain, encrypted, sizeof(plain)) != 0);
	px_decrypt_db_block(encrypted, decrypted, 0x1234, sizeof(plain), 7);
	assert(memcmp(plain, decrypted, sizeof(plain)) == 0);

	px_encrypt_mb_block(plain, encrypted, 0x5678, sizeof(plain));
	assert(memcmp(plain, encrypted, sizeof(plain)) != 0);
	px_decrypt_mb_block(encrypted, decrypted, 0x5678, sizeof(plain));
	assert(memcmp(plain, decrypted, sizeof(plain)) == 0);

	return 0;
}
