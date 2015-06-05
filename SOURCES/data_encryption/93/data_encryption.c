/*
 * Transparent Data Encryption for PostgreSQL Free Edition
 *
 * Copyright (c) 2015 NEC Corporation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>

#include "postgres.h"
#include "fmgr.h"
#include "utils/guc.h"
#include "utils/palloc.h"
#include "utils/builtins.h"
#include "utils/bytea.h"
#include "commands/explain.h"
#include "tcop/tcopprot.h"
#include "mb/pg_wchar.h"
#include "access/hash.h"
#include "libpq/pqformat.h"

#include "pgcrypto.h"

#include "data_encryption.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif /* END PG_MODULE_MAGIC */

/* enable encryption/decryption function */
static bool encrypt_enable = true;

/* checking log_statement is 'all' or not */
static bool encrypt_checklogparam = true;

/* backup of encryption key */
static char *encrypt_backup = "";

/* backup of log_statement value */
int save_log_statement = -1;

/* backup of log_min_error_statement value*/
int save_log_min_error_statement = -1;

/* backup of log_min_duration_statemet value */
int save_log_min_duration_statement = -1;

/* current encryption key */
key_info *newest_key_info = NULL;
/* previous encryption key */
key_info *old_key_info = NULL;
const short header = 1;

void
_PG_init(void)
{
	DefineCustomBoolVariable("encrypt.enable",
			"encryption on/off.",
			NULL,
			&encrypt_enable,
			true,
			PGC_USERSET,
			0,
			NULL,
			NULL,
			NULL);

	DefineCustomBoolVariable("encrypt.checklogparam",
			"log_statement check on/off.",
			NULL,
			&encrypt_checklogparam,
			true,
			PGC_SUSET,
			0,
			NULL,
			NULL,
			NULL);

	DefineCustomStringVariable("encrypt.backup",
			"cipher key backup directory path.",
			NULL,
			&encrypt_backup,
			"",
			PGC_SUSET,
			0,
			NULL,
			NULL,
			NULL);
}

void
_PG_fini(void)
{

}


/*
 * Function : enctext_in
 * ---------------------
 * returns ciphertext of input data(text)
 *
 * @param	*char ARG[0]		input data(plaintext)
 * @return	ciphertext of input data
 */
PG_FUNCTION_INFO_V1(enctext_in);

Datum
enctext_in(PG_FUNCTION_ARGS)
{
	char     *input_text = PG_GETARG_CSTRING(0);    /* input plain text parameter */

	bytea    *encrypted_data = NULL; /* encryption data */
	bytea    *result = NULL;         /* header + encyrpted_data  */
	bytea    *tmp_data = NULL;
	bytea    *tmp_key = NULL;
	text     *tmp_algorithm = NULL;

	/* if encrypt_enable is true, encrypting plain text and return */
	if (encrypt_enable) {
		/* if key is not set print error and exit */
		if (newest_key_info == NULL) {
			ereport(ERROR,
				(errcode(ERRCODE_IO_ERROR),
				errmsg("TDE-E0016 could not encrypt data, because key was not set(01)")));
		}

		/* get key and encryption algorithm and encrypt data */
		tmp_data = (bytea *) DatumGetPointer(DirectFunctionCall1(textin, CStringGetDatum(input_text)));
		tmp_key = (bytea *) DatumGetPointer(DirectFunctionCall1(byteain, CStringGetDatum(newest_key_info->key)));
		tmp_algorithm = cstring_to_text(newest_key_info->algorithm);
		encrypted_data = (bytea *)
						DatumGetPointer(DirectFunctionCall3(pg_encrypt,
							PointerGetDatum(tmp_data),
							PointerGetDatum(tmp_key),
							PointerGetDatum(tmp_algorithm)));

		pfree(tmp_data);
		pfree(tmp_key);
		pfree(tmp_algorithm);

		/* add header(dummy) to encrypted data */
		result = (bytea *) palloc(VARSIZE(encrypted_data) + sizeof(short));
		SET_VARSIZE(result, VARSIZE(encrypted_data) + sizeof(short));
		memcpy(VARDATA(result), &header, sizeof(short));
		memcpy((VARDATA(result) + sizeof(short)), VARDATA_ANY(encrypted_data), VARSIZE_ANY_EXHDR(encrypted_data));

		pfree(encrypted_data);

		PG_RETURN_BYTEA_P(result);
	}
	/* if encrypt_enable is not true return plain text */
	else {
		PG_RETURN_DATUM(DirectFunctionCall1(byteain, CStringGetDatum(input_text)));
	}
}


/*
 * Function : enctext_out
 * ---------------------
 * returns plaintext of input data
 *
 * @param	*char ARG[0]	input data(ciphertext)
 * @return	plaintext of input data(text)
 */
PG_FUNCTION_INFO_V1(enctext_out);

Datum
enctext_out(PG_FUNCTION_ARGS)
{
	bytea *vlena = PG_GETARG_BYTEA_PP(0); /* pointer of input ciphertext  */

	bytea *encrypted_data = NULL;  /* remove header of ciphertext */
	key_info *entry = NULL;           /* key */
	Datum result;
	Datum tmp_result;
	bytea *tmp_key = NULL;
	text *tmp_algorithm = NULL;

	/* if encrypt_enable is true, decrypt input data and return */
	if (encrypt_enable) {
		/* if key is not set print error and exit */
		if (newest_key_info == NULL) {
			ereport(ERROR,
				(errcode(ERRCODE_IO_ERROR),
				errmsg("TDE-E0017 could not decrypt data, because key was not set(01)")));
		}

		/* if old key is exists, re-encryption is working now */
		if (old_key_info != NULL) {
			entry = old_key_info;
		} else {
			entry = newest_key_info;
		}

		/* remove header from input data */
		encrypted_data = (bytea *)palloc(VARSIZE_ANY_EXHDR(vlena) - sizeof(short) + VARHDRSZ);
		SET_VARSIZE(encrypted_data, VARSIZE_ANY_EXHDR(vlena) - sizeof(short) + VARHDRSZ);
		memcpy(VARDATA(encrypted_data), (VARDATA_ANY(vlena) + sizeof(short)), VARSIZE_ANY_EXHDR(vlena) - sizeof(short));

		/* decrypting ciphertext */
		tmp_key = (bytea *) DatumGetPointer(DirectFunctionCall1(byteain, CStringGetDatum(entry->key)));
		tmp_algorithm = cstring_to_text(entry->algorithm);
		tmp_result = DirectFunctionCall3(pg_decrypt,
										PointerGetDatum(encrypted_data),
										PointerGetDatum(tmp_key),
										PointerGetDatum(tmp_algorithm));
		result = DirectFunctionCall1(textout, tmp_result);

		pfree(encrypted_data);
		pfree(DatumGetPointer(tmp_result));
		pfree(tmp_key);
		pfree(tmp_algorithm);
	}
	/* if encrypt_enable is false return ciphertext */
	else {
		result = DirectFunctionCall1(byteaout, PointerGetDatum(vlena));
	}

	PG_FREE_IF_COPY(vlena, 0);

	PG_RETURN_DATUM(result);
}


/*
 * Function : encbytea_in
 * ---------------------
 * returns ciphertext of input data(binary)
 *
 * @param	*char ARG[0]	input data(plaintext)
 * @return	ciphertext of input data
 */
PG_FUNCTION_INFO_V1(encbytea_in);

Datum
encbytea_in(PG_FUNCTION_ARGS)
{
	char     *input_text = PG_GETARG_CSTRING(0);  /* input plain text parameter */

	bytea    *encrypted_data = NULL; /* encryption data */
	bytea    *result = NULL;         /* header + encrypted_data */
	bytea    *tmp_data = NULL;
	bytea    *tmp_key = NULL;
	text     *tmp_algorithm = NULL;

	/* if encrypt_enable is true, encrypting plain text and return */
	if (encrypt_enable) {
		/* if key is not set print error and exit */
		if (newest_key_info == NULL) {
			ereport(ERROR,
				(errcode(ERRCODE_IO_ERROR),
				errmsg("TDE-E0016 could not encrypt data, because key was not set(02)")));
		}

		/* get key and encryption algorithm and encrypt data */
		tmp_data = (bytea *) DatumGetPointer(DirectFunctionCall1(byteain, CStringGetDatum(input_text)));
		tmp_key = (bytea *) DatumGetPointer(DirectFunctionCall1(byteain, CStringGetDatum(newest_key_info->key)));
		tmp_algorithm = cstring_to_text(newest_key_info->algorithm);
		encrypted_data = (bytea *)
						DatumGetPointer(DirectFunctionCall3(pg_encrypt,
							PointerGetDatum(tmp_data),
							PointerGetDatum(tmp_key),
							PointerGetDatum(tmp_algorithm)));

		pfree(tmp_data);
		pfree(tmp_key);
		pfree(tmp_algorithm);

		/* add header information to encrypted data */
		result = (bytea *) palloc(VARSIZE(encrypted_data) + sizeof(short));
		SET_VARSIZE(result, VARSIZE(encrypted_data) + sizeof(short));
		memcpy(VARDATA(result), &header, sizeof(short));
		memcpy((VARDATA(result) + sizeof(short)), VARDATA_ANY(encrypted_data), VARSIZE_ANY_EXHDR(encrypted_data));

		pfree(encrypted_data);

		PG_RETURN_BYTEA_P(result);
	}
	/* if encrypt_enable is not true return plain text */
	else {
		PG_RETURN_DATUM(DirectFunctionCall1(byteain, CStringGetDatum(input_text)));
	}
}


/*
 * Function : encbytea_out
 * ---------------------
 * returns plaintext of input data
 *
 * @param	*char ARG[0]		input data(ciphertext)
 * @return	plaintext of input data(binary)
 */
PG_FUNCTION_INFO_V1(encbytea_out);

Datum
encbytea_out(PG_FUNCTION_ARGS)
{
	bytea *vlena = PG_GETARG_BYTEA_PP(0); /* pointer of input ciphertext  */

	bytea *encrypted_data = NULL;  /* remove header of ciphertext */
	key_info *entry = NULL;           /* key */
	Datum result;
	Datum tmp_result;
	bytea *tmp_key = NULL;
	text *tmp_algorithm = NULL;

	/* if encrypt_enable is true, decrypt input data and return */
	if (encrypt_enable) {
		/* if key is not set print error and exit */
		if (newest_key_info == NULL) {
			ereport(ERROR,
				(errcode(ERRCODE_IO_ERROR),
				errmsg("TDE-E0017 could not decrypt data, because key was not set(02)")));
		}

		if (old_key_info != NULL) {
			entry = old_key_info;
		} else {
			entry = newest_key_info;
		}

		/* remove header information from input data */
		encrypted_data = (bytea *)palloc(VARSIZE_ANY_EXHDR(vlena) - sizeof(short) + VARHDRSZ);
		SET_VARSIZE(encrypted_data, VARSIZE_ANY_EXHDR(vlena) - sizeof(short) + VARHDRSZ);
		memcpy(VARDATA(encrypted_data), (VARDATA_ANY(vlena) + sizeof(short)), VARSIZE_ANY_EXHDR(vlena) - sizeof(short));

		/* decrypting ciphertext */
		tmp_key = (bytea *) DatumGetPointer(DirectFunctionCall1(byteain, CStringGetDatum(entry->key)));
		tmp_algorithm = cstring_to_text(entry->algorithm);
		tmp_result = DirectFunctionCall3(pg_decrypt, 
										PointerGetDatum(encrypted_data),
										PointerGetDatum(tmp_key),
										PointerGetDatum(tmp_algorithm));
		result = DirectFunctionCall1(byteaout, tmp_result);

		pfree(encrypted_data);
		pfree(DatumGetPointer(tmp_result));
		pfree(tmp_key);
		pfree(tmp_algorithm);
	}
	/* if encrypt_enable is false return ciphertext */
	else {
		result = DirectFunctionCall1(byteaout, PointerGetDatum(vlena));
	}

	PG_FREE_IF_COPY(vlena, 0);

	PG_RETURN_DATUM(result);
}


/*
 * Function : enc_compeq_enctext
 * ---------------------
 * return true if two input ciphertext are equal
 *
 * @param	*bytea ARG[0]	input data1(cipher text)
 * @param	*bytea ARG[1]	input data2(cipher text)
 * @return	true ARG[0] and ARG[1] are equal
 */
PG_FUNCTION_INFO_V1(enc_compeq_enctext);

Datum
enc_compeq_enctext(PG_FUNCTION_ARGS)
{
	bytea *barg1  = NULL;
	bytea *barg2  = NULL;

	int len1 = 0;
	int len2 = 0;
	bool result = true;

	barg1 = PG_GETARG_BYTEA_PP(0);
	barg2 = PG_GETARG_BYTEA_PP(1);

	len1 = VARSIZE_ANY_EXHDR(barg1);
	len2 = VARSIZE_ANY_EXHDR(barg2);
	/* return false, if length of barg1 and barg2 are different */
	if (len1 != len2) {
		result  = false;
	}
	else {
		result = (memcmp(VARDATA_ANY(barg1), VARDATA_ANY(barg2), len1) == 0);
	}

	PG_FREE_IF_COPY(barg1, 0);
	PG_FREE_IF_COPY(barg2, 1);

	PG_RETURN_BOOL(result);
}

/*
 * Function : enc_compeq_text_enctext
 * ---------------------
 * return true if input plaintext and ciphertext are equal
 *
 * @param	*text ARG[0]		input data1(plain text)
 * @param	*bytea ARG[1]		input data2(cipher text)
 * @return	true ARG[0] and ARG[1] are equal
 */
PG_FUNCTION_INFO_V1(enc_compeq_text_enctext);

Datum
enc_compeq_text_enctext(PG_FUNCTION_ARGS)
{
	text *arg1 = PG_GETARG_TEXT_PP(0);
	text *arg2 = NULL;
	Datum tmp;

	bool result = true;

	tmp = DirectFunctionCall1(enctext_out, PG_GETARG_DATUM(1));
	arg2 = (text *) DatumGetPointer(DirectFunctionCall1(textin, tmp));
	pfree(DatumGetPointer(tmp));

	if (VARSIZE_ANY_EXHDR(arg1) != VARSIZE_ANY_EXHDR(arg2)) {
		result = false;
	}
	else {
		result = (strncmp(VARDATA_ANY(arg1), VARDATA_ANY(arg2), VARSIZE_ANY_EXHDR(arg1)) == 0);
	}

	PG_FREE_IF_COPY(arg1, 0);
	PG_FREE_IF_COPY(arg2, 1);

	PG_RETURN_BOOL(result);
}


/*
 * Function : enc_compeq_enctext_text
 * ---------------------
 * return true if input ciphertext and plainrtext are equal
 *
 * @param	*bytea ARG[0]	input data1(cipher text)
 * @param	*text ARG[1]		input data2(plain text)
 * @return	true ARG[0] and ARG[0] are equal
 */
PG_FUNCTION_INFO_V1(enc_compeq_enctext_text);

Datum
enc_compeq_enctext_text(PG_FUNCTION_ARGS)
{
	text *arg1 = NULL;
	text *arg2 = PG_GETARG_TEXT_PP(1);
	Datum tmp;

	bool result = true;

	tmp = DirectFunctionCall1(enctext_out, PG_GETARG_DATUM(0));
	arg1 = (text *) DatumGetPointer(DirectFunctionCall1(textin, tmp));
	pfree(DatumGetPointer(tmp));

	if (VARSIZE_ANY_EXHDR(arg1) != VARSIZE_ANY_EXHDR(arg2)) {
		result = false;
	}
	else {
		result = (strncmp(VARDATA_ANY(arg1), VARDATA_ANY(arg2), VARSIZE_ANY_EXHDR(arg2)) == 0);
	}

	PG_FREE_IF_COPY(arg1, 0);
	PG_FREE_IF_COPY(arg2, 1);

	PG_RETURN_BOOL(result);
}


/*
 * Function : enc_compeq_encbytea
 * ---------------------
 * return true if two binary input ciphertext are equal
 *
 * @param	*bytea ARG[0]	input data1(cipher text)
 * @param	*bytea ARG[1]	input data2(cipher text)
 * @return	true if it is true ARG[0] and ARG[1] are equal
 */
PG_FUNCTION_INFO_V1(enc_compeq_encbytea);

Datum
enc_compeq_encbytea(PG_FUNCTION_ARGS)
{
	bytea *arg1  = PG_GETARG_BYTEA_PP(0);
	bytea *arg2  = PG_GETARG_BYTEA_PP(1);

	int len1 = 0;
	int len2 = 0;
	bool result = true;

	len1 = VARSIZE_ANY_EXHDR(arg1);
	len2 = VARSIZE_ANY_EXHDR(arg2);

	/* return false, if length of barg1 and barg2 are different */
	if (len1 != len2) {
		result = false;
	}
	else {
		result = (memcmp(VARDATA_ANY(arg1), VARDATA_ANY(arg2), len1) == 0);
	}

	PG_FREE_IF_COPY(arg1, 0);
	PG_FREE_IF_COPY(arg2, 1);

	PG_RETURN_BOOL(result);
}


/*
 * Function : enc_compeq_bytea_encbytea
 * ---------------------
 * return true if input binary plaintext and binary ciphertext are equal
 *
 * @param	*bytea ARG[0]		input data1(plain text)
 * @param	*bytea ARG[1]		input data2(cipher text)
 * @return	true ARG[0] and ARG[1] are equal
 */
PG_FUNCTION_INFO_V1(enc_compeq_bytea_encbytea);

Datum
enc_compeq_bytea_encbytea(PG_FUNCTION_ARGS)
{
	bytea *arg1  = PG_GETARG_BYTEA_PP(0);
	bytea *arg2  = NULL;
	Datum tmp;

	int len1 = 0;
	int len2 = 0;
	bool result = true;

	tmp = DirectFunctionCall1(encbytea_out, PG_GETARG_DATUM(1));
	arg2 = (bytea *) DatumGetPointer(DirectFunctionCall1(byteain, tmp));
	pfree(DatumGetPointer(tmp));

	len1 = VARSIZE_ANY_EXHDR(arg1);
	len2 = VARSIZE_ANY_EXHDR(arg2);

	/* return false, if length of barg1 and barg2 are different */
	if (len1 != len2) {
		result = false;
	}
	else {
		result = (memcmp(VARDATA_ANY(arg1), VARDATA_ANY(arg2), len1) == 0);
	}

	PG_FREE_IF_COPY(arg1, 0);
	PG_FREE_IF_COPY(arg2, 1);

	PG_RETURN_BOOL(result);
}


/*
 * Function : enc_compeq_encbytea_bytea
 * ---------------------
 * return true if input binary ciphertext and binary plaintext are equal
 *
 * @param	*bytea ARG[0]	input data1(cipher text)
 * @param	*bytea ARG[1]		input data2(plain text)
 * @return	true, if it is true ARG[0] and ARG[0] are equal
 */
PG_FUNCTION_INFO_V1(enc_compeq_encbytea_bytea);

Datum
enc_compeq_encbytea_bytea(PG_FUNCTION_ARGS)
{
	bytea *arg1  = NULL;
	bytea *arg2  = PG_GETARG_BYTEA_PP(1);
	Datum tmp;

	int len1 = 0;
	int len2 = 0;
	bool result = true;

	tmp = DirectFunctionCall1(encbytea_out, PG_GETARG_DATUM(0));
	arg1 = (bytea *) DatumGetPointer(DirectFunctionCall1(byteain, tmp));
	pfree(DatumGetPointer(tmp));

	len1 = VARSIZE_ANY_EXHDR(arg1);
	len2 = VARSIZE_ANY_EXHDR(arg2);

	/* return false, if length of barg1 and barg2 are different */
	if (len1 != len2) {
		result = false;
	}
	else {
		result = (memcmp(VARDATA_ANY(arg1), VARDATA_ANY(arg2), len2) == 0);
	}

	PG_FREE_IF_COPY(arg1, 0);
	PG_FREE_IF_COPY(arg2, 1);

	PG_RETURN_BOOL(result);
}


/*
 * Function : enc_hash_encdata
 * ---------------------
 * return hash value of input cipher text(text/binary)
 *
 * @param	varlena ARG[0]	value for create hash
 * @return	hash value of input data
 */
PG_FUNCTION_INFO_V1(enc_hash_encdata);

Datum
enc_hash_encdata(PG_FUNCTION_ARGS)
{
	struct varlena *key = PG_GETARG_VARLENA_PP(0);

	Datum  result;

	result = hash_any((unsigned char *) VARDATA_ANY(key),
					VARSIZE_ANY_EXHDR(key));

	/* avoiding leaking memory for toasted input */
	PG_FREE_IF_COPY(key, 0);

	return result;
}


/*
 * Function : enc_store_key_info
 * ---------------------
 * regist newest_key_info
 *
 * @param	*text ARG[0]	encryption key
 * @param	*text ARG[1]	encryption algorithm
 */
PG_FUNCTION_INFO_V1(enc_store_key_info);

Datum
enc_store_key_info(PG_FUNCTION_ARGS)
{
	text *key = PG_GETARG_TEXT_P(0); /* encryption key */
	text *algorithm = PG_GETARG_TEXT_P(1); /* encryption algorithm */

	/* memory allocation */
	key_info *entry = (key_info *) malloc(sizeof(key_info));

	/* store key information to entry */
	entry->key = (char *) strdup(text_to_cstring(key));
	entry->algorithm = (char *) strdup(text_to_cstring(algorithm));

	/* update lastest key with specified new key information */
	newest_key_info = entry;

	PG_RETURN_BOOL(TRUE);
}


/*
 * Function : enc_store_old_key_info
 * ---------------------
 * regist old_key_info
 *
 * @param	*text ARG[0]	old encryption key
 * @param	*text ARG[1]	old encryption algorithm
 * @return	address of old key information
 */
PG_FUNCTION_INFO_V1(enc_store_old_key_info);

Datum
enc_store_old_key_info(PG_FUNCTION_ARGS)
{
	text *key = PG_GETARG_TEXT_P(0); /* encryption key */
	text *algorithm = PG_GETARG_TEXT_P(1); /* encryption algorithm */

	/* memory allocation */
	key_info *entry = malloc(sizeof(key_info));

	/* store key information to entry */
	entry->key = (char *) strdup(text_to_cstring(key));
	entry->algorithm = (char *) strdup(text_to_cstring(algorithm));

	/* set old key information */
	old_key_info = entry;

	PG_RETURN_BOOL(TRUE);
}


/* Function : enc_drop_key_info
 * ---------------------
 * drop cipher key information from memory
 */
PG_FUNCTION_INFO_V1(enc_drop_key_info);
bool
enc_drop_key_info(void)
{
	if (newest_key_info != NULL) {
		if (newest_key_info->key != NULL) {
			free(newest_key_info->key);
		}
		if (newest_key_info->algorithm != NULL) {
			free(newest_key_info->algorithm);
		}
		free(newest_key_info);
		newest_key_info = NULL;

		PG_RETURN_BOOL(TRUE);
	}
	else {
		PG_RETURN_BOOL(FALSE);
	}
}


/*
 * Function : enc_drop_old_key_info
 * ---------------------
 * clear of old key information
 * @return false if old key is already set
 */
PG_FUNCTION_INFO_V1(enc_drop_old_key_info);

Datum
enc_drop_old_key_info(void)
{
	if (old_key_info != NULL) {
		if (old_key_info->key != NULL) {
			free(old_key_info->key);
		}
		if (old_key_info->algorithm != NULL) {
			free(old_key_info->algorithm);
		}
		free(old_key_info);
		old_key_info = NULL;

		PG_RETURN_BOOL(TRUE);
	}
	else {
		PG_RETURN_BOOL(FALSE);
	}
}

/*
 * Function : enc_rename_backupfile
 * ---------------------
 * check existing of encryption key backup file(arg0).
 * if there is backup, rename to arg1
 *
 * @param char* ARG[0]	file name of backup
 * @param char* ARG[1]	file name of older backup
 * @return true if rename is successfully done or there is no backup.
 */
PG_FUNCTION_INFO_V1(enc_rename_backupfile);

Datum
enc_rename_backupfile(PG_FUNCTION_ARGS)
{
	char *new_filepath = text_to_cstring(PG_GETARG_TEXT_P(0)); /* file name of backup */
	char *old_filepath = text_to_cstring(PG_GETARG_TEXT_P(1)); /* file name of older backup */

	/* if backup is exist */
	if (access(new_filepath, F_OK) == 0) {
		/* if older backup is exist */
		if (access(old_filepath, F_OK) == 0) {
			/* remove older backup */
			if (remove(old_filepath) != 0) {
				/* returns false if removing older backcup is failed */
				PG_RETURN_BOOL(FALSE);
			}
		}

		/* rename backup file */
		if (rename(new_filepath, old_filepath) != 0) {
			/* returns false if renaming arg0 to arg1 is failed */
			PG_RETURN_BOOL(FALSE);
		}
	}

	pfree(new_filepath);
	pfree(old_filepath);

	PG_RETURN_BOOL(TRUE);

}


/*
 * Function : enc_save_logsetting
 * ---------------------
 * backup current parameters of log_statement, log_min_error_statement and log_min_duration_statement
 *
 * @return true if parameters are backuped successfully
 */
PG_FUNCTION_INFO_V1(enc_save_logsetting);

Datum
enc_save_logsetting(void)
{
	/* if backup of current parameters are not exist */
	if(save_log_statement == -1 && save_log_min_error_statement == -1 &&
		save_log_min_duration_statement == -1){
		/* backup current parameters */
		save_log_statement = log_statement;
		save_log_min_error_statement = log_min_error_statement;
		save_log_min_duration_statement = log_min_duration_statement;

		/* setting parameters, "do not log details"  */
		log_statement = LOGSTMT_NONE;
		log_min_error_statement = PANIC;
		log_min_duration_statement = -1;
	}
	/* if parameters are already backuped */
	else{
		PG_RETURN_BOOL(FALSE);
	}

	PG_RETURN_BOOL(TRUE);
}


/*
 * Function : enc_restore_logsetting
 * ---------------------
 * restore log parameters from backup of parameters
 *
 * @return true if backup of parameters are exist
 */
PG_FUNCTION_INFO_V1(enc_restore_logsetting);

Datum
enc_restore_logsetting(PG_FUNCTION_ARGS)
{
	/* return false, backcup of log parameters are not exist */
	if(save_log_statement == -1 && save_log_min_error_statement == -1 &&
		save_log_min_duration_statement == -1){
		PG_RETURN_BOOL(FALSE);
	}
	else{
		/* restore log parameters from backup of parameters */
		log_statement = save_log_statement;
		log_min_error_statement = save_log_min_error_statement;
		log_min_duration_statement = save_log_min_duration_statement;

		/* init backup of parameters */
		save_log_statement = -1;
		save_log_min_error_statement = -1;
		save_log_min_duration_statement = -1;
	}

	PG_RETURN_BOOL(TRUE);

}


PG_FUNCTION_INFO_V1(encrecv);
/*
 *		copy from PostgreSQL 9.3.6(backend/utils/adt/varlena.c)
 *		bytearecv			- converts external binary format to bytea
 */
Datum
encrecv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);
	bytea	   *result;
	int			nbytes;

	nbytes = buf->len - buf->cursor;
	result = (bytea *) palloc(nbytes + VARHDRSZ);
	SET_VARSIZE(result, nbytes + VARHDRSZ);
	pq_copymsgbytes(buf, VARDATA(result), nbytes);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(encsend);
/*
 *		copy from PostgreSQL 9.3.6(backend/utils/adt/varlena.c)
 *		byteasend			- converts bytea to binary format
 *
 * This is a special case: just copy the input...
 */
Datum
encsend(PG_FUNCTION_ARGS)
{
	bytea	   *vlena = PG_GETARG_BYTEA_P_COPY(0);

	PG_RETURN_BYTEA_P(vlena);
}
