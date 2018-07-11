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
#include "pgstat.h"
#include "utils/guc.h"
#include "utils/palloc.h"
#include "utils/builtins.h"
#include "utils/bytea.h"
#include "commands/explain.h"
#include "tcop/tcopprot.h"
#include "mb/pg_wchar.h"
#include "access/hash.h"
#include "libpq/pqformat.h"
#include "utils/memutils.h"
#include "catalog/pg_collation.h"

/* Support logical replication in linux environment */
#if (!defined(WIN32)) && (PG_VERSION_NUM >= 100000)
#include "replication/walsender.h"
#include "replication/logicalworker.h"
#endif

#include "pgcrypto.h"
#include "px.h"

#include "data_encryption.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif /* END PG_MODULE_MAGIC */

/* enable encryption/decryption function */
static bool encrypt_enable = true;

/* backup of encryption key */
static char *encrypt_backup = "";

/* whether mask pgtde_begin_session query log or not */
static bool encrypt_mask_cipherkeylog = false;

/* backup of log_min_error_statement value*/
int save_log_min_error_statement = -1;

/* backup of log_min_duration_statemet value */
int save_log_min_duration_statement = -1;

/* current encryption key */
key_info *newest_key_info = NULL;
/* previous encryption key */
key_info *old_key_info = NULL;
const short header = 1;

/* mask log messages */
static void suppress_cipherkeylog_hook(ErrorData *);

/* backup the old one */
static emit_log_hook_type prev_emit_log_hook = NULL;

/* protect from recursive call */
static bool being_hook = false;
static bool isLoaded = false;

void
_PG_init(void)
{
	/* 
	* _PG_init is only need call one time, when postmaster start 
	*/
	
	if(isLoaded){
		return;
	}
	/* set loaded flag to true */
	isLoaded = true;

	/* load hook module */
	prev_emit_log_hook = emit_log_hook;
	emit_log_hook = suppress_cipherkeylog_hook;

	DefineCustomBoolVariable("encrypt.mask_cipherkeylog",
			"mask query log messages, string within () mark will be masked by *****",
			NULL,
			&encrypt_mask_cipherkeylog,
			false,
			PGC_SUSET,
			0,
			NULL,
			NULL,
			NULL);

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
	/* restore emit_log_hook when unload */
	if (emit_log_hook == suppress_cipherkeylog_hook){
		emit_log_hook = prev_emit_log_hook;
	}
}

/* mask cipherkeylog hook */
/*
 * Function : suppress_cipherkeylog_hook
 * ---------------------
 * Mask query log messages.
 * String in "()" mark will be quoted by *****.
 *
 * @param	*char ARG[0]		input ErrorData*
 * @return	nothing
 */
static void
suppress_cipherkeylog_hook(ErrorData *edata){
	/*
	 * These temporary variables below are allocated in ErrorContext.
	 * PostgreSQL do not reset ErrorContext when elevel is not in
	 * ERROR, FATAL, PANIC. So we must pfree in this case.
	 */
	Datum convertedMsg, replaceMsg_tmp, regex, regex_param, mask, flag;
	MemoryContext old_mem_context;

	/* call the old one if exist */
	if (prev_emit_log_hook){
		prev_emit_log_hook(edata);
	}

	if(encrypt_mask_cipherkeylog && !(being_hook)){
		/* Arguments of textregexreplace.*/
		regex = CStringGetTextDatum("[(].+[)]"),
		mask  = CStringGetTextDatum("(*****)"),
		flag  = CStringGetTextDatum("g");

		/* protect from recursive call */
		being_hook = true;
		/* mask STATEMENT error messages */
		if(debug_query_string){
			replaceMsg_tmp = CStringGetTextDatum(debug_query_string);
			convertedMsg = DirectFunctionCall4Coll(textregexreplace,
					C_COLLATION_OID,
					replaceMsg_tmp,
					regex,
					mask,
					flag);
			if(replaceMsg_tmp){
				px_memset((void*)replaceMsg_tmp,0,strlen(DatumGetCString(replaceMsg_tmp)));
				pfree((void*)replaceMsg_tmp);
			}
			if (MessageContext)
			{
				old_mem_context = MemoryContextSwitchTo(MessageContext);
				debug_query_string = TextDatumGetCString(convertedMsg);
				MemoryContextSwitchTo(old_mem_context);
			}
			else
			{
				/* In case of MessageContext == NULL 
 				* e.g when parallel worker is running */
				debug_query_string = TextDatumGetCString(convertedMsg);
			}
			if(convertedMsg){
				pfree((void*)convertedMsg);
			}
		}

		/* mask normal log messages */
		if(edata->message){
			replaceMsg_tmp = CStringGetTextDatum(edata->message);
			convertedMsg = DirectFunctionCall4Coll(textregexreplace,
					C_COLLATION_OID,
					replaceMsg_tmp,
					regex,
					mask,
					flag);
			if(replaceMsg_tmp){
				px_memset((void*)replaceMsg_tmp,0,strlen(DatumGetCString(replaceMsg_tmp)));
				pfree((void*)replaceMsg_tmp);
			}
			/* do not leave anything relate to key info in memory*/
			px_memset(edata->message,0,strlen((char*)edata->message));
			pfree(edata->message);
			edata->message = TextDatumGetCString(convertedMsg);
			if(convertedMsg){
				pfree((void*)convertedMsg);
			}
		}

		/* mask DETAIL error message
		 * edata->detail_log never include any query message.
		 * so we just mask only edata->detail.
		 */
		if(edata->detail){
			replaceMsg_tmp = CStringGetTextDatum(edata->detail);
			convertedMsg = DirectFunctionCall4Coll(textregexreplace,
					C_COLLATION_OID,
					replaceMsg_tmp,
					regex,
					mask,
					flag);
			if(replaceMsg_tmp){
				px_memset((void*)replaceMsg_tmp,0,strlen(DatumGetCString(replaceMsg_tmp)));
				pfree((void*)replaceMsg_tmp);
			}
			/* The following must be execute only in extension protocol.
			* But can not judge whether extension protocol or not */
			regex_param = CStringGetTextDatum("parameters: .+");
			replaceMsg_tmp = DirectFunctionCall4Coll(textregexreplace,
				C_COLLATION_OID,
				convertedMsg,
				regex_param,
				mask,
				flag);
			if(convertedMsg){
				px_memset((void*)convertedMsg,0,strlen(DatumGetCString(convertedMsg)));
				pfree((void*)convertedMsg);
			}
			if(regex_param){
				pfree((void*)regex_param);
			}
			/* do not leave anything relate to key info in memory*/
			px_memset(edata->detail,0,strlen((char*)edata->detail));
			pfree(edata->detail);
			edata->detail = TextDatumGetCString(replaceMsg_tmp);
			if(replaceMsg_tmp){
				pfree((void*)replaceMsg_tmp);
			}
		}

		/* QUERY error message
		 * if a sql in function failed, then the query is printed as QUERY message.
		 */
		if(edata->internalquery){
			replaceMsg_tmp = CStringGetTextDatum(edata->internalquery);
			convertedMsg = DirectFunctionCall4Coll(textregexreplace,
				C_COLLATION_OID,
				replaceMsg_tmp,
				regex,
				mask,
				flag);
			if(replaceMsg_tmp){
				px_memset((void*)replaceMsg_tmp,0,strlen(DatumGetCString(replaceMsg_tmp)));
				pfree((void*)replaceMsg_tmp);
			}
			/* do not leave anything relate to key info in memory*/
			px_memset(edata->internalquery,0,strlen((char*)edata->internalquery));
			pfree(edata->internalquery);
			edata->internalquery = TextDatumGetCString(convertedMsg);
			if(convertedMsg){
				pfree((void*)convertedMsg);
			}
		}

		/* QUERY context message
		 * cipher key is included in edata->context messages. So it must be masked
		 */
		if(edata->context){
			replaceMsg_tmp = CStringGetTextDatum(edata->context);
				convertedMsg = DirectFunctionCall4Coll(textregexreplace,
				C_COLLATION_OID,
				replaceMsg_tmp,
				regex,
				mask,
				flag);
			if(replaceMsg_tmp){
				px_memset((void*)replaceMsg_tmp,0,strlen(DatumGetCString(replaceMsg_tmp)));
				pfree((void*)replaceMsg_tmp);
			}
			/* do not leave anything relate to key info in memory*/
			px_memset(edata->context,0,strlen((char*)edata->context));
			pfree(edata->context);
			edata->context = TextDatumGetCString(convertedMsg);
			if(convertedMsg){
				pfree((void*)convertedMsg);
			}
		}
		if(regex)
			pfree((void*)regex);
		if(mask)
			pfree((void*)mask);
		if(flag)
			pfree((void*)flag);
		/* protect from recursive call */
		being_hook = false;
	}
}

/*
 * Function : mask_activity
 * ---------------------
 * masked pg_stat_activity's query column to specify text.
 *
 * @param	nothing
 * @return	nothing
 */
PG_FUNCTION_INFO_V1(mask_activity);
Datum
mask_activity(PG_FUNCTION_ARGS)
{
	elog(DEBUG2,"TDE-D0002 masking pg_stat_activity's query.");
	pgstat_report_activity(STATE_RUNNING,"<query masking...>");

	PG_RETURN_VOID();
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
	bytea    *plain_data = NULL;

#if (!defined(WIN32)) && (PG_VERSION_NUM >= 100000)
	/* If encrypt_enable and i am not logical worker, encrypting plain text and return */
	if (encrypt_enable && !IsLogicalWorker()) 
#else
	/* if encrypt_enable is true, encrypting plain text and return */
	if (encrypt_enable) 
#endif
	{
		plain_data = (bytea *) DatumGetPointer(DirectFunctionCall1(textin, CStringGetDatum(input_text)));
		encrypted_data = pgtde_encrypt(plain_data);
		pfree(plain_data);

		/* add header(dummy) to encrypted data */
		result = add_header_to_result(encrypted_data);
		pfree(encrypted_data);

		PG_RETURN_BYTEA_P(result);
	}
	/* if not return plain text */
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
	bytea *input_data = PG_GETARG_BYTEA_PP(0); /* pointer of input ciphertext  */
	bytea *encrypted_data = NULL;  /* remove header of ciphertext */
	key_info *entry = NULL;           /* key */
	Datum result;
	Datum tmp_result;


#if (!defined(WIN32)) && (PG_VERSION_NUM >= 100000)
	/* if encrypt_enable and i am not walsender, decrypt input data and return */
	if (encrypt_enable && !am_walsender )
#else
	/* if encrypt_enable is true, decrypt input data and return */
	if (encrypt_enable)
#endif		
	{
		/* if old key is exists, re-encryption is working now */
		if (old_key_info != NULL) {
			entry = old_key_info;
		} else {
			entry = newest_key_info;
		}

		/* remove header from input data */
		encrypted_data = remove_header_from_inputdata(input_data);
		/* decrypting ciphertext */
		tmp_result = pgtde_decrypt(entry, encrypted_data);
		result = DirectFunctionCall1(textout, tmp_result);

		pfree(encrypted_data);
		pfree(DatumGetPointer(tmp_result));
	}
	/* if not return ciphertext */
	else {
		result = DirectFunctionCall1(byteaout, PointerGetDatum(input_data));
	}

	PG_FREE_IF_COPY(input_data, 0);

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
	bytea    *plain_data = NULL;


#if (!defined(WIN32)) && (PG_VERSION_NUM >= 100000)
	/* If encrypt_enable and i am not logical worker, encrypting plain text and return */	
	if (encrypt_enable && !IsLogicalWorker()) 
#else
	/* if encrypt_enable is true, encrypting plain text and return */
	if (encrypt_enable) 
#endif
	{
		/* get key and encryption algorithm and encrypt data */
		plain_data = (bytea *) DatumGetPointer(DirectFunctionCall1(byteain, CStringGetDatum(input_text)));
		encrypted_data = pgtde_encrypt(plain_data);
		pfree(plain_data);
		/* add header information to encrypted data */
		result = add_header_to_result(encrypted_data);
		pfree(encrypted_data);
		PG_RETURN_BYTEA_P(result);
	}
	/* if not return plain text */
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
	bytea *input_data = PG_GETARG_BYTEA_PP(0); /* pointer of input ciphertext  */

	bytea *encrypted_data = NULL;  /* remove header of ciphertext */
	key_info *entry = NULL;           /* key */
	Datum result;
	Datum tmp_result;

#if (!defined(WIN32)) && (PG_VERSION_NUM >= 100000)
	/* if encrypt_enable and i am not walsender, decrypt input data and return */
	if (encrypt_enable && !am_walsender )
#else
	/* if encrypt_enable is true, decrypt input data and return */
	if (encrypt_enable)
#endif
	{
		/* if key is not set print error and exit */
		if (old_key_info != NULL) {
			entry = old_key_info;
		} else {
			entry = newest_key_info;
		}

		/* remove header information from input data */
		encrypted_data = remove_header_from_inputdata(input_data);

		/* decrypting ciphertext */
		tmp_result = pgtde_decrypt(entry, encrypted_data);
		result = DirectFunctionCall1(byteaout, tmp_result);

		pfree(encrypted_data);
		pfree(DatumGetPointer(tmp_result));
	}
	/* if not return ciphertext */
	else {
		result = DirectFunctionCall1(byteaout, PointerGetDatum(input_data));
	}

	PG_FREE_IF_COPY(input_data, 0);
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
	bytea *barg1  = PG_GETARG_BYTEA_PP(0);
	bytea *barg2  = PG_GETARG_BYTEA_PP(1);
	bool result = cmp_binary(barg1, barg2);
	PG_FREE_IF_COPY(barg1, 0);
	PG_FREE_IF_COPY(barg2, 1);

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
	bytea *barg1  = PG_GETARG_BYTEA_PP(0);
	bytea *barg2  = PG_GETARG_BYTEA_PP(1);
	bool result = cmp_binary(barg1, barg2);

	PG_FREE_IF_COPY(barg1, 0);
	PG_FREE_IF_COPY(barg2, 1);

	PG_RETURN_BOOL(result);
}

/* cast function */
PG_FUNCTION_INFO_V1(boolenctext);
Datum
boolenctext(PG_FUNCTION_ARGS)
{
	bool arg1 = PG_GETARG_BOOL(0);
	const char *str;

	if (arg1) {
		str = "true";
	} else {
		str = "false";
	}

	PG_RETURN_DATUM(DirectFunctionCall1(enctext_in, CStringGetDatum(str)));
}

PG_FUNCTION_INFO_V1(enctextrtrim);
Datum
enctextrtrim(PG_FUNCTION_ARGS)
{
	text   *str = (text *)DatumGetPointer(DirectFunctionCall1(rtrim1, PG_GETARG_DATUM(0)));

	PG_RETURN_DATUM(DirectFunctionCall1(enctext_in, CStringGetDatum(text_to_cstring(str))));
}

PG_FUNCTION_INFO_V1(inetenctext);
Datum
inetenctext(PG_FUNCTION_ARGS)
{
	text   *str = (text *)DatumGetPointer(DirectFunctionCall1(network_show, PG_GETARG_DATUM(0)));

	PG_RETURN_DATUM(DirectFunctionCall1(enctext_in, CStringGetDatum(text_to_cstring(str))));
}

PG_FUNCTION_INFO_V1(xmlenctext);
Datum
xmlenctext(PG_FUNCTION_ARGS)
{
	text   *str = (text *)PG_GETARG_TEXT_PP(0);

	PG_RETURN_DATUM(DirectFunctionCall1(enctext_in, CStringGetDatum(text_to_cstring(str))));
}

PG_FUNCTION_INFO_V1(enctext_regclass);
Datum
enctext_regclass(PG_FUNCTION_ARGS)
{
	char *str = NULL;

	str = (char *)DatumGetCString(DirectFunctionCall1(enctext_out, PG_GETARG_DATUM(0)));

	PG_RETURN_DATUM(DirectFunctionCall1(text_regclass, PointerGetDatum(cstring_to_text((str)))));
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

key_info* create_key_info(text* key, text* algorithm) {
	key_info* entry;
	MemoryContext old_mem_context;

	/* cipher key must be stored in TopMemoryContext */
	old_mem_context = MemoryContextSwitchTo(TopMemoryContext);
	entry =(key_info*) palloc(sizeof(key_info));

	entry->key = (bytea *) palloc(VARSIZE(key));
	memcpy((char *) entry->key, (char *) key, VARSIZE(key));

	entry->algorithm = (text *) palloc(VARSIZE(algorithm));
	memcpy((char *) entry->algorithm, (char *) algorithm, VARSIZE(algorithm));

	MemoryContextSwitchTo(old_mem_context);

	return entry;
}

bool
drop_key_info(key_info* entry) {
	if(entry != NULL) {
		if (entry->key != NULL) {
				/* do not leave anything relate to key info in memory*/
				px_memset(entry->key,0,VARSIZE(entry->key));
				pfree(entry->key);
			}
			if (entry->algorithm != NULL) {
				pfree(entry->algorithm);
			}
			pfree(entry);
			return true;
	}
	return false;
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

	drop_key_info(newest_key_info);
	/* set current key information */
	newest_key_info = create_key_info(key, algorithm);

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

	drop_key_info(old_key_info);
	/* set old key information */
	old_key_info = create_key_info(key, algorithm);

	PG_RETURN_BOOL(TRUE);
}


/* Function : enc_drop_key_info
 * ---------------------
 * drop cipher key information from memory
 */
PG_FUNCTION_INFO_V1(enc_drop_key_info);
Datum
enc_drop_key_info(PG_FUNCTION_ARGS)
{
	if(drop_key_info(newest_key_info)){
		newest_key_info = NULL;
		PG_RETURN_BOOL(TRUE);
	}
	PG_RETURN_BOOL(FALSE);
}


/*
 * Function : enc_drop_old_key_info
 * ---------------------
 * clear of old key information
 * @return false if old key is already set
 */
PG_FUNCTION_INFO_V1(enc_drop_old_key_info);

Datum
enc_drop_old_key_info(PG_FUNCTION_ARGS)
{
	if(drop_key_info(old_key_info)){
		old_key_info = NULL;
		PG_RETURN_BOOL(TRUE);
	}
	PG_RETURN_BOOL(FALSE);
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

/* return true, if encryption key is set */
bool
is_session_opened() {
	/* if key is not set return false */
	if (newest_key_info == NULL) {
		return false;
	}
	return true;
}


/* encrypt input_data using lastest key and return */
bytea* pgtde_encrypt(bytea* input_data) {
	if(!is_session_opened()){
		ereport(ERROR, (errcode(ERRCODE_IO_ERROR),
					errmsg("TDE-E0016 could not encrypt data, because key was not set[01]")));
	}
	bytea *encrypted_data = (bytea *) DatumGetPointer(DirectFunctionCall3(pg_encrypt,
				PointerGetDatum(input_data), PointerGetDatum(newest_key_info->key),
				PointerGetDatum(newest_key_info->algorithm)));
	return encrypted_data;
}

/* decrypt encrypted_data using entry and return */
Datum pgtde_decrypt(key_info* entry, bytea* encrypted_data) {
	if(!is_session_opened()){
		ereport(ERROR, (errcode(ERRCODE_IO_ERROR),
					errmsg("TDE-E0017 could not decrypt data, because key was not set[01]")));
	}
	Datum result = DirectFunctionCall3(pg_decrypt, PointerGetDatum(encrypted_data),
			PointerGetDatum(entry->key), PointerGetDatum(entry->algorithm));
	return result;
}

/* add header to encrypted data */
bytea* add_header_to_result(bytea* encrypted_data) {
	bytea* result = NULL;
	result = (bytea *) palloc(VARSIZE(encrypted_data) + sizeof(short));
	/* add key header information to encrypted data */
	SET_VARSIZE(result, VARSIZE(encrypted_data) + sizeof(short));
	memcpy(VARDATA(result), &header, sizeof(short));
	memcpy((VARDATA(result) + sizeof(short)), VARDATA_ANY(encrypted_data),
			VARSIZE_ANY_EXHDR(encrypted_data));
	return result;
}

/* remove header from input data */
bytea* remove_header_from_inputdata(bytea* input_data) {
	bytea* encrypted_data = NULL;
	/* remove version from input data */
	encrypted_data = (bytea *) palloc(
			VARSIZE_ANY_EXHDR(input_data) - sizeof(short) + VARHDRSZ);
	SET_VARSIZE(encrypted_data,
			VARSIZE_ANY_EXHDR(input_data) - sizeof(short) + VARHDRSZ);
	memcpy(VARDATA(encrypted_data), (VARDATA_ANY(input_data) + sizeof(short)),
			VARSIZE_ANY_EXHDR(input_data) - sizeof(short));
	return encrypted_data;
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

/* return true , if barg1 and barg2 are equal */
bool cmp_binary(bytea* barg1, bytea* barg2) {
	int len1 = VARSIZE_ANY_EXHDR(barg1);
	int len2 = VARSIZE_ANY_EXHDR(barg2);
	bool result;
	/* return false, if length of barg1 and barg2 are different */
	if (len1 != len2) {
		result = false;
	} else {
		result = (memcmp(VARDATA_ANY(barg1), VARDATA_ANY(barg2), len1) == 0);
	}
	return result;
}
