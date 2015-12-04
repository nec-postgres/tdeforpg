#! /bin/bash

###################################################
#            Setting Necessary Path.              #
###################################################
export PROGRAMNAME=`basename $0`
#get program root path
export CURRENTPATH=`echo $0|sed "s/${PROGRAMNAME}$//g"`

#change directory to program root
if [ -n "$CURRENTPATH" ]; then
    cd $CURRENTPATH
fi

#set external program(psql) execution path 
export PGPATH=$1
export LD_PRELOAD=${PGPATH}/lib/libpq.so.5

#set the psql path
export PSQLPATH=${PGPATH}/bin/

export PATH=${PSQLPATH}:${PATH}
export KEYTBL="cipher_key_table"


###################################################
#            Setting PSQL Environment             #
###################################################
export PGOPTIONS="-c client_min_messages=ERROR"

###################################################
#           Input PSQL Parameter Function         #
###################################################
input_psql_param(){
  echo "=== Database connection information ===";
  #set the delimiter to newline
  OLDIFS="${IFS}"
  IFS=$'\n'
  echo -n 'Please enter database server port to connect : '
  read PORT;

  echo -n 'Please enter database user name to connect : '
  read USER;

  echo -n 'Please enter password for authentication : '
  stty -echo
  read PASS;
  stty echo
  echo 

  echo -n 'Please enter database name to connect : '
  read DB;
  if [ "${DB}" = "template1" ];then echo "ERROR: Can not use template1 database";exit 1;fi
  if [ "${DB}" = "" ];then echo "ERROR: The length of database name must not be zero";exit 1;fi
  IFS="${OLDIFS}"

  export PGHOST=localhost
  export PGDATABASE="${DB}"
  export PGPORT="${PORT}"
  export PGPASSWORD="${PASS}"
  export PGUSER="${USER}"

  return 0;
}

#####################################################
#           Connection Test Function                #
#####################################################
connection_test(){
  psql -w -c "select 1" 1>/dev/null ;
  return $?
}

#####################################################
#           Register New Cipher Key Function          #
#####################################################
cipher_key_regist(){
  #set the delimiter to newline
  OLDIFS="${IFS}"
  IFS=$'\n'

  echo "=== Regist new cipher key ===";
  NUMBER_OF_KEY=`psql -t -c "SELECT COUNT(*) FROM ${KEYTBL};"`
  if [ $NUMBER_OF_KEY -ge 1 ]; then
    echo -n 'Please enter the current cipher key : '
    stty -echo
    read CURRENT_CIPHER_KEY
    stty echo
    echo
  else
    CURRENT_CIPHER_KEY='init'
  fi

  echo -n 'Please enter the new cipher key : '
  stty -echo
  read NEW_CIPHER_KEY;
  stty echo
  echo

  echo -n 'Please retype the new cipher key : '
  stty -echo
  read RETYPE_NEW_CIPHER_KEY;
  stty echo
  echo
  if [ "$RETYPE_NEW_CIPHER_KEY" != "$NEW_CIPHER_KEY" ]; then
    echo 'Cipher key do not match'
    exit;
  fi

  echo -n 'Please enter the algorithm for new cipher key : '
  read ALGORITHM;
  echo
  while true; do
    echo -n 'Are you sure to register new cipher key(y/n) : '
    read SELECT;
    case $SELECT in
      [Yy] ) break;;
      [Nn] ) exit;;
      * ) echo "Please enter y or n";;
    esac
  done

(psql -w <<EOF
     select cipher_key_disable_log();
     select cipher_key_regist('${CURRENT_CIPHER_KEY}', '${NEW_CIPHER_KEY}','${ALGORITHM}');
     select cipher_key_enable_log();
EOF
) 1>/dev/null

  return $?
}

#####################################################
#           Connection Test Function                #
#####################################################
connection_test(){
  psql -w -c "select 1" 1>/dev/null ;
  return $?
}

###################################################
#                    Main Process                 #
###################################################
1>/dev/null
if [ $# -ne 1 ]; then
    echo "usage: sh bin/cipher_key_regist.sh POSTGRESQL_DIR"
    echo "Please specify PostgreSQL installed directory"
    exit 1
fi

#input connection parameter for psql
input_psql_param

#connection test
connection_test  
if [ $? -ne 0 ];then
  echo "ERROR: Could not connect to the database";
  exit 1;
fi

#check existing of cipher_key_table
CIPHER_EXIST=`psql -t -c "SELECT COUNT(*) FROM PG_TABLES WHERE TABLENAME='${KEYTBL}';"`
if [ $CIPHER_EXIST -eq 0 ]; then
  echo "ERROR: Transparent data encryption feature has not been activated yet"
  exit 1;
fi 

cipher_key_regist
