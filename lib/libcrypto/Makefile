# *****************************************************************************
# * Copyright (c) 2015-2020 IBM Corporation
# * All rights reserved.
# * This program and the accompanying materials
# * are made available under the terms of the BSD License
# * which accompanies this distribution, and is available at
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Contributors:
# *     IBM Corporation - initial implementation
# ****************************************************************************/

TOPCMNDIR ?= ../..

CPPFLAGS = -I../libc/include $(CPUARCHDEF) -I$(INCLBRDDIR) \
	   -I$(INCLCMNDIR) -I$(INCLCMNDIR)/$(CPUARCH) -I$(SLOFCMNDIR)
CPPFLAGS += -I. -I./mbedtls/include -DMBEDTLS_CONFIG_FILE="\"slof-mbed-config.h\""

LDFLAGS = -nostdlib

TARGET = ../libcrypto.a


all: $(TARGET)

SRCS = appended_sig.c \
       mbedtls/library/platform_util.c \
       mbedtls/library/sha256.c mbedtls/library/sha512.c mbedtls/library/pkcs7.c \
       mbedtls/library/asn1parse.c \
       mbedtls/library/x509.c mbedtls/library/x509_crt.c mbedtls/library/x509_crl.c \
       mbedtls/library/pk.c mbedtls/library/pk_wrap.c mbedtls/library/pkparse.c \
       mbedtls/library/md.c mbedtls/library/md_wrap.c \
       mbedtls/library/oid.c \
       mbedtls/library/rsa.c mbedtls/library/rsa_internal.c \
       mbedtls/library/bignum.c


OBJS = $(SRCS:%.c=%.o)

$(TARGET): $(OBJS)
	$(AR) -rc $@ $(OBJS)
	$(RANLIB) $@

clean:
	$(RM) $(TARGET) $(OBJS)

distclean: clean
	$(RM) Makefile.dep


# Rules for creating the dependency file:
depend:
	$(RM) Makefile.dep
	$(MAKE) Makefile.dep

Makefile.dep: Makefile
	$(CC) -M $(CPPFLAGS) $(CFLAGS) $(SRCS) $(SRCSS) > Makefile.dep

# Include dependency file if available:
-include Makefile.dep
