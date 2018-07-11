#! /bin/bash
#data_encryption module build script

TDEVERSION=1.2.1.0
CURR_PATH=`pwd`
PGVERSION=$1
SPATH=$2
AESNI="pgcrypto-aes-ni"

cd $PGVERSION
CDIR=`pwd`

rm -f Makefile
cp Makefile.in Makefile

#set path from Makefile if SPATH is not set
if [ -z $SPATH ];
then
  SPATH=`cat Makefile |grep ^PGSQL_SRC_PATH|cut -f3 -d" "`
fi

PGCRYPTO_PATH=${SPATH}/contrib/pgcrypto

############  build pgcrypto  ###########
# prepare support aes-ni pgcrypto for PostgreSQL 9.6, 9.5 with back-port source
if [ "$PGVERSION" -eq "96" \
	-o "$PGVERSION" -eq "95"  ]; then
	
	if [ -d ${PGCRYPTO_PATH}.bk ]; then
		# may be it was interrupted in previous time. Do nothing
		:
	else
		# backup original pgcrypto
		cp ${PGCRYPTO_PATH} ${PGCRYPTO_PATH}.bk -rf
	fi

	# if not already fixed
	if [ ! -f ${PGCRYPTO_PATH}/aes-ni-fixed ]; then
		# back-port
		cp  ${CURR_PATH}/${AESNI}/openssl.c ${PGCRYPTO_PATH}/ -f
		cd ${PGCRYPTO_PATH}
		patch < ${CURR_PATH}/${AESNI}/pgp-encrypt.patch
		touch ${PGCRYPTO_PATH}/aes-ni-fixed
	fi
fi

# build pgcrypto
cd ${PGCRYPTO_PATH}
make clean
rm -f libpgcrypto.so
make
cp -f pgcrypto.so ${CDIR}/libpgcrypto${PGVERSION}.so.${TDEVERSION}
ldd pgcrypto.so | grep "libcrypto.so.10"
if [  $? -eq 1 ]; then
	if [ "$PGVERSION" -ne "93" -a "$PGVERSION" -ne "94"  ]; then
        echo "WARNING: not built with AES-NI. PostgreSQL must be configured with --with-openssl to support AES-NI.";
	fi
fi

cd ${CDIR}

#build data_encryption
make clean
make PGSQL_SRC_PATH=${SPATH}
mv data_encryption.so data_encryption${PGVERSION}.so.${TDEVERSION}

# add debug link to data_encryption.so in release mode
if [ -f data_encryption.debug ]; then
	mv data_encryption.debug data_encryption${PGVERSION}.debug.${TDEVERSION}
	objcopy --add-gnu-debuglink=data_encryption${PGVERSION}.debug.${TDEVERSION} data_encryption${PGVERSION}.so.${TDEVERSION}
fi

ldd data_encryption${PGVERSION}.so.${TDEVERSION}

# move back the directory
if [ "$PGVERSION" -eq "95" -o "$PGVERSION" -eq "96" ] && [ -d "${PGCRYPTO_PATH}.bk" ] 
then
	rm -rf ${PGCRYPTO_PATH};
	mv ${PGCRYPTO_PATH}.bk ${PGCRYPTO_PATH};
fi

if [ ! -f data_encryption${PGVERSION}.so.${TDEVERSION} ];
then
  echo "ERROR: cannot make data_encryption.so"
  exit 1;
fi

echo
echo "INFO: data_encryption.so was made."
echo
