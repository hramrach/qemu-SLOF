// appended_sig.c

#include <libcrypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mbedtls/pkcs7.h>
#include "certificate.h"
#include "../../slof/paflof.h"

static char appsig_magic[] = "~Module signature appended~\n";

struct module_signature {
	uint8_t		algo;		/* Public-key crypto algorithm [0] */
	uint8_t		hash;		/* Digest algorithm [0] */
	uint8_t		id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	uint8_t		signer_len;	/* Length of signer's name [0] */
	uint8_t		key_id_len;	/* Length of key identifier [0] */
	uint8_t		__pad[3];
	uint32_t	sig_len;	/* Length of signature data */
};

int is_secureboot() {
	// only verify if in secure-boot mode.
	// todo - oh so much, especially error handling
	forth_eval("s\" /\" find-device s\" ibm,secure-boot\" get-node get-property");
	if (forth_pop() == -1)
		return 0;
	forth_pop();
	if (*(int32_t *)forth_pop() < 2)
		return 0;
	return 1;
}

static int verify_one_cert(mbedtls_pkcs7 *pkcs7, const void *blob, size_t bloblen, const void *cert, size_t certlen, const char *certdesc)
{
	mbedtls_x509_crt *x509 = malloc(sizeof(mbedtls_x509_crt));
	int rc = 0;

	mbedtls_x509_crt_init(x509);
	printf("%d\n", __LINE__);
	rc = mbedtls_x509_crt_parse_der(x509, cert, certlen);
	if (rc) {
		printf("%d\n", __LINE__);

		printf("Appended signature: internal error parsing %s x509 certificate.\n", certdesc);
		rc = 0;
		goto exit_x509;
	}
	printf("%d\n", __LINE__);

	rc = mbedtls_pkcs7_signed_data_verify(pkcs7, x509, blob, bloblen);
	printf("Appended signature: %sverified by %s x509 certificate.\n", rc ? "NOT " : "" , certdesc);
	if (rc) {
		printf("%d\n", __LINE__);
		rc = 0;
		goto exit_x509;
	}

	rc = 1;

exit_x509:
	mbedtls_x509_crt_free(x509);
	free(x509);

	return rc;
}

int verify_appended_signature(void *blob, size_t len) {
	void *ptr;
	mbedtls_pkcs7 *pkcs7;
	int rc = 0;
	struct module_signature *modsig;

	if (!is_secureboot())
		return 1;

	// go to start of magic
	ptr = blob + (len - sizeof(appsig_magic) + 1); // appsig_magic contains null-term

	// again be careful not to require the null terminator
	if (strncmp(ptr, appsig_magic, sizeof(appsig_magic) - 1)) {
		printf("Appended signature: magic string missing. Aborting.\n");
		return 0;
	}

	// now load the sig info
	ptr -= sizeof(struct module_signature);
	modsig = (struct module_signature *)ptr;

	printf("%x %x %x %x %x\n", modsig->algo, modsig->hash, modsig->id_type, modsig->key_id_len, modsig->signer_len);
	if (modsig->id_type != 2) { // pkcs7
		printf("Appended signature: unexpected format (not PKCS#7). Aborting.\n");
		return 0;
	}

	if (modsig->algo != 0 || modsig->hash != 0 || modsig->key_id_len != 0 || modsig->signer_len != 0) {
		printf("Appended signature: unexpected parameter inconsistend with PKCS#7. Aborting.\n");
		return 0;
	}

	// point at the pkcs7 data itself:
	ptr -= modsig->sig_len;

	printf("%d\n", __LINE__);
	printf("ptr at %p, blob at %p, computed len %lu ? %lu\n", ptr, blob, len-(ptr-blob), (unsigned long)(ptr-blob));

	// load into the pkcs7 code
	pkcs7 = malloc(sizeof(mbedtls_pkcs7));
	mbedtls_pkcs7_init(pkcs7);

	rc = mbedtls_pkcs7_parse_der(ptr, modsig->sig_len, pkcs7);
	if (rc != MBEDTLS_PKCS7_SIGNED_DATA) {
		printf("Appended signature: error parsing PKCS#7 data: %d. Aborting.\n", rc);
		rc = 0;
		goto exit;
	}
	printf("%d\n", __LINE__);

	rc = verify_one_cert(pkcs7, blob, (ptr-blob), certificate_SLE_crt, certificate_SLE_crt_len, "SLE");
	if (rc)
	    goto exit;

	rc = verify_one_cert(pkcs7, blob, (ptr-blob), certificate_der, certificate_der_len, "project");
	if (rc)
	    goto exit;

	printf("%d\n", __LINE__);
	printf("Appended signature: verification failed. Refusing to proceed.\n");
exit:
	mbedtls_pkcs7_free(pkcs7);
	free(pkcs7);
	return rc;
}
