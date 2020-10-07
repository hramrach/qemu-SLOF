// libcrypto.h

#include <stddef.h>

int is_secureboot(void);

int verify_appended_signature(void *blob, size_t len);