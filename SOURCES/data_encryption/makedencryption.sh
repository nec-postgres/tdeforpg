#! /bin/bash
#data_encryption module build script

TDEVERSION=1.1.1.1
PGVERSION=$1
SPATH=$2

cd $PGVERSION
CDIR=`pwd`

#set path from Makefile if SPATH is not set
if [ -z $SPATH ];
then
  SPATH=`cat Makefile |grep ^PGSQL_SRC_PATH|cut -f3 -d" "`
fi

#build data_encryption
make clean
make PGSQL_SRC_PATH=${SPATH}
mv data_encryption.so data_encryption${PGVERSION}.so.${TDEVERSION}
ldd data_encryption${PGVERSION}.so.${TDEVERSION}

echo
if [ ! -f data_encryption${PGVERSION}.so.${TDEVERSION} ];
then
  echo "ERROR: cannot make data_encryption.so"
  exit 1;
fi

echo "INFO: data_encryption.so was made."
echo
