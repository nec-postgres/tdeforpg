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
#set initscript path
export SCRPATH=../lib/init
#activate db file directory path
export INSTPATH=../sys

#PostgreSQL version number
PGVERSION=

export PATH=${PSQLPATH}:${PATH}


###################################################
#            Setting PSQL Environment             #
###################################################
export PGOPTIONS="-c client_min_messages=ERROR"


###################################################
#            Setting Common Variable              #
###################################################
export KEYTBL="cipher_key_table"
export NOKEYTBL="cipher_key_table_uninst"

export ERRFILE="error_`date +%Y%m%d-%H%M%S`.log"

###################################################
#           Input PSQL Parameter Function         #
###################################################
input_psql_param(){

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
#           File Exist Test Function                #
#####################################################
file_exist_check(){
  if [ ! -f "$1" ];
  then
    echo "ERROR: There is not exist a definition-script : $1"
    rm -f "${INSTALLFILE}"
    exit 1;
  fi
}

#####################################################
#            Decide Function                        #
#####################################################
decide(){
    prompt="Please input [Yes/No] > "
    status=0

    while : ; do
      line=""
      read  -p "${prompt}" line
      case "$line" in
        Y|y|[Yy]es|YES)
            status=0
            break
            ;;
        N|n|[Nn]o|NO)
            status=1
            break
            ;;
       esac

       echo "ERROR: Invalid input."
    done

    return $status
}

###################################################
#        Output Parameter Function                #
###################################################
printErr(){
  echo "error occured at `date +%Y-%m-%d-%H:%M:%S`"
  echo "parameters:"
  echo "  user:${PGUSER}"
  echo "  db:${PGDATABASE}"
  echo "  port:${PGPORT}"
  echo "  menu:$select"
  echo
}

###################################################
#                Validate Function                #
###################################################
validate(){

  ########
  #  initial activate    …  true
  #  reactivate      …  false
  ########
  VALIDATE_NEW=false

  #input connection parameter for psql
  input_psql_param

  #connection test
  connection_test
  if [ $? -ne 0 ];
  then
    echo "ERROR: Could not connect to the database";  
    exit 1;
  fi

  # get PGVERSION
  PGVERSION=`psql -t -c "show server_version_num;"` 

  #check existing of cipher_key_table
  CIPHER_EXIST=`psql -t -c "SELECT COUNT(*) FROM PG_TABLES WHERE TABLENAME='${KEYTBL}';"`
  if [ $CIPHER_EXIST -eq 1 ];
  then
    echo "WARN: Transparent data encryption function has already been activated"
    exit 0;
  fi   


  #store all activation query to file for execution
  INSTALLFILE="${INSTPATH}"/"${DB}".cipher.inst
  if [ -f "${INSTALLFILE}" ];
  then
    echo "ERROR: Lock file already exists. File name: ${INSTALLFILE}"
    echo "HINT:  Remove the Lock file, and Try again"
    exit 1;
  fi

  #check existing of cipher_key_table_uninst
  CIPHER_NOEXIST=`psql -t -c "SELECT COUNT(*) FROM PG_TABLES WHERE TABLENAME='${NOKEYTBL}';"`
  if [ $CIPHER_NOEXIST -ne 0 ];
  then
    #exits -- reactivate 
    VALIDATE_NEW=false
    echo "WARN: Are you sure you want to reactivate  the transparent data encryption feature? "
    decide
    if [ $? -eq 1 ];
    then
      echo "INFO: terminated"
      exit 0;
    fi


    #init activation file
    echo "" > "${INSTALLFILE}"
	#only root can read this file
	chmod 600 "${INSTALLFILE}"
    #remove installation file, if installation is terminated abnormally  
    trap 'rm -f "${INSTALLFILE}"; exit 1;' 1 2 3 15
    #rename cipher_key_table_uninst to cipher_key_table
    QUERY="ALTER TABLE \"${NOKEYTBL}\" RENAME TO \"${KEYTBL}\";";
    echo "${QUERY}" >> "${INSTALLFILE}"
  else
   #not exists -- initial activate
    VALIDATE_NEW=true
    #execute CREATE LANGUAGE
    psql -c "CREATE OR REPLACE LANGUAGE plpgsql;" 2> /dev/null

    file_exist_check "${SCRPATH}/cipher_definition.sql"
    file_exist_check "${SCRPATH}/cipher_key_function.sql"

    #init activation file
    echo "" > "${INSTALLFILE}"
	#only root can read this file
	chmod 600 "${INSTALLFILE}"
    #remove installation file, if installation is terminated abnormally
    trap 'rm -f "${INSTALLFILE}"; exit 1;' 1 2 3 15    
    cat "${SCRPATH}/cipher_definition.sql" >> "${INSTALLFILE}"
    cat "${SCRPATH}/cipher_key_function.sql" >> "${INSTALLFILE}" 
    echo "GRANT SELECT ON cipher_key_table TO PUBLIC;" >> "${INSTALLFILE}"
  fi

  file_exist_check "${SCRPATH}/common_session_create.sql"
  #define session function A
  cat "${SCRPATH}/common_session_create.sql" >> "${INSTALLFILE}"
	
  # add parallel safe setting for PostgreSQL 9.6 and greater
  if [ ${PGVERSION} -ge 90600 ]; then
      file_exist_check "${SCRPATH}/pgtde_parallel_safe_setting.sql"
	  cat "${SCRPATH}/pgtde_parallel_safe_setting.sql" >> "${INSTALLFILE}"
  fi

  #run all query in installation file using transaction
  psql --set ON_ERROR_STOP=ON -1 -f "${INSTALLFILE}" 1>/dev/null 2>"${ERRFILE}"
  if [ `wc -c < ${ERRFILE}` -gt 0 ];
  then
    printErr >> "${ERRFILE}"
    echo "ERROR: Could not activate  transparent data encryption feature"
    echo "HINT : Please see ${ERRFILE} for detail" 
    rm -f "${INSTALLFILE}"
    exit 1;
  fi
  
  #empty the INSTALLFILE
  echo " " > "${INSTALLFILE}"
  
  #remove empty error log
  rm -rf "${ERRFILE}"

  echo "INFO: Transparent data encryption feature has been activated"

  return 0;
}

###################################################
#              Invalidate Function                #
###################################################
invalidate(){


  #input connection parameters for psql
  input_psql_param
  
  #connection test
  connection_test
  if [ $? -ne 0 ];then echo "ERROR: Could not connect to the database";exit 1;fi

  #check existence of cipher_key_table
  CIPHER_EXIST=`psql -t -c "SELECT COUNT(*) FROM PG_TABLES WHERE TABLENAME='${KEYTBL}';"` 
  if [ $CIPHER_EXIST -eq 0 ];
  then  #cipher_key_table is not exists
    echo "WARN: Transparent data encryption feature has not been activated yet"
    exit 0
  fi

  #store all query for inactivate to file
  INSTALLFILE="${INSTPATH}"/"${DB}".cipher.inst
  if [ ! -f "${INSTALLFILE}" ];
  then
    echo "ERROR: Lock file does not exist. File name : ${INSTALLFILE}"
    exit 1;
  fi
  #init inactivate file
  echo "" > "${INSTALLFILE}"
  #only root can read this file
  chmod 600 "${INSTALLFILE}"
  #drop session function C
  echo "DROP FUNCTION PGTDE_BEGIN_SESSION(TEXT);" >> "${INSTALLFILE}"
  #drop end session function
  echo "DROP FUNCTION PGTDE_END_SESSION();" >> "${INSTALLFILE}"
  


  #rename cipher_key_table 
  QUERY="ALTER TABLE \"${KEYTBL}\" RENAME TO \"${NOKEYTBL}\";";
  echo "${QUERY}" >> "${INSTALLFILE}"


  #run all query in inactivation file using transaction
  psql --set ON_ERROR_STOP=ON -1 -f "${INSTALLFILE}" 1>/dev/null 2>"${ERRFILE}"
  if [ `wc -c < ${ERRFILE}` -gt 0 ];
  then
    printErr >> "${ERRFILE}"
    echo "ERROR: Could not inactivate the transparent data encryption feature"
    echo "HINT : Please see ${ERRFILE} for detail" 
    exit 1;
  fi
  #remove empty error log
  rm -rf "${ERRFILE}"

  #remove dbname.cipher.inst
  rm -f "${INSTALLFILE}"

  echo "INFO: The transparent data encryption feature has been inactivated"

  return 0;
}


###################################################
#                 Main Process                    #
###################################################

if [ $# -ne 1 ]; then
    echo "usage: sh bin/cipher_setup.sh POSTGRESQL_DIR"
    echo "Please specify PostgreSQL installed directory"
    exit 1
fi

echo "Transparent data encryption feature setup script"
echo "Please select from the setup menu below"


while [ 1 ]
do
  echo 'Transparent data encryption feature setup menu'
  echo '1: activate  the transparent data encryption feature'
  echo '2: inactivate the transparent data encryption feature'
  prompt="select menu [1 - 2] > "
  read -p "${prompt}" select

  case $select in
    1) 
     validate;break
     ;;
    2) 
     invalidate;break
     ;;
    *)  
      echo "ERROR: Invalid menu number : $select"
      continue;
      ;;
  esac
done
