/*------------------------------------------------------------*
 * cipher_key_definition
 * 
 * define type, function, index end etc for TDE.
 *------------------------------------------------------------*/

SET search_path TO public;
SET check_function_bodies TO off;


/* define a new procedural language */
/* CREATE TRUSTED LANGUAGE 'plpgsql' HANDLER language_handler_in;*/

	/* drop if encrypted data types are already exist */
	--DROP TYPE IF EXISTS encrypt_text CASCADE;
	--DROP TYPE IF EXISTS encrypt_bytea CASCADE;

	/* create encrypted data types */
	CREATE TYPE encrypt_text;
	CREATE TYPE encrypt_bytea;

	/* define input function of encrypted text type */
	CREATE FUNCTION
		enctext_in(cstring)
	RETURNS
		encrypt_text
	AS
		'/usr/lib64/data_encryption.so','enctext_in'
	LANGUAGE C STABLE STRICT;

	/* define output function of encrypted text type */
	CREATE FUNCTION
		enctext_out(encrypt_text)
	RETURNS
		cstring
	AS
		'/usr/lib64/data_encryption.so','enctext_out'
	LANGUAGE C STABLE STRICT;

	/* define recv function of encrypted text type */
	CREATE FUNCTION 
		enctext_recv(internal)
	RETURNS
		encrypt_text
	AS
		'/usr/lib64/data_encryption.so','encrecv'
	LANGUAGE C IMMUTABLE STRICT;

	/* define send function of encrypted text type */
	CREATE FUNCTION 
		enctext_send(encrypt_text)
	RETURNS
		bytea
	AS
		'/usr/lib64/data_encryption.so','encsend'
	LANGUAGE C IMMUTABLE STRICT;

	/* define input function of encrypted binary type */
	CREATE FUNCTION
		encbytea_in(cstring)
	RETURNS
		encrypt_bytea
	AS
		'/usr/lib64/data_encryption.so','encbytea_in'
	LANGUAGE C STABLE STRICT;

	/* define output function of encrypted binary type */
	CREATE FUNCTION
		encbytea_out(encrypt_bytea)
	RETURNS
		cstring
	AS
		'/usr/lib64/data_encryption.so','encbytea_out'
	LANGUAGE C STABLE STRICT;
	
	/* define recv function of encrypted binary type */
	CREATE FUNCTION 
		encbytea_recv(internal)
	RETURNS
		encrypt_bytea
	AS
		'/usr/lib64/data_encryption.so','encrecv'
	LANGUAGE C IMMUTABLE STRICT;

	/* define send function of encrypted binary type */
	CREATE FUNCTION 
		encbytea_send(encrypt_bytea)
	RETURNS
		bytea
	AS
		'/usr/lib64/data_encryption.so','encsend'
	LANGUAGE C IMMUTABLE STRICT;

	/* define encrypted text types */
	CREATE TYPE ENCRYPT_TEXT (
		INPUT = enctext_in
		, OUTPUT = enctext_out
		, RECEIVE = enctext_recv
		, SEND = enctext_send
		, INTERNALLENGTH = VARIABLE
		, ALIGNMENT = int4
		, STORAGE = extended
		, CATEGORY = 'S');

	/* define encrypted binary types */
	CREATE TYPE ENCRYPT_BYTEA (
		INPUT = encbytea_in
		, OUTPUT = encbytea_out
		, RECEIVE = encbytea_recv
		, SEND = encbytea_send
		, INTERNALLENGTH = VARIABLE
		, ALIGNMENT = int4
		, STORAGE = extended
		, CATEGORY = 'U');

	/* index operator of encrypted text types */
	CREATE OR REPLACE FUNCTION
		enc_compeq_enctext(encrypt_text,encrypt_text)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_compeq_enctext'
	LANGUAGE C STABLE STRICT;

	/* index operator of encrypted binary types */
	CREATE OR REPLACE FUNCTION
		enc_compeq_encbytea(encrypt_bytea,encrypt_bytea)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_compeq_encbytea'
	LANGUAGE C STABLE STRICT;

	/* hash function for encrypted text */
	CREATE OR REPLACE FUNCTION
		enc_hash_enctext(encrypt_text)
	RETURNS
		integer
	AS
		'/usr/lib64/data_encryption.so','enc_hash_encdata'
	LANGUAGE C STRICT IMMUTABLE;

	/* hash function for encrypted binary */
	CREATE OR REPLACE FUNCTION
		enc_hash_encbytea(encrypt_bytea)
	RETURNS
		integer
	AS
		'/usr/lib64/data_encryption.so','enc_hash_encdata'
	LANGUAGE C STRICT IMMUTABLE;

	/* load current encryption key */
	CREATE OR REPLACE FUNCTION
		enc_store_key_info(text, text)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_store_key_info'
	LANGUAGE C STRICT;
	
	/* load old key to memory for re-encryption */
	CREATE OR REPLACE FUNCTION
		enc_store_old_key_info(text, text)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_store_old_key_info'
	LANGUAGE C STRICT;

	/* drops key information from memory */
	CREATE OR REPLACE FUNCTION
		enc_drop_key_info()
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_drop_key_info'
	LANGUAGE C STRICT;

	/* drops old key information from memory  */
	CREATE OR REPLACE FUNCTION
		enc_drop_old_key_info()
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_drop_old_key_info'
	LANGUAGE C STRICT;

	/* rename bakcup file, if it is exists */
	CREATE OR REPLACE FUNCTION
		enc_rename_backupfile(text,text)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_rename_backupfile'
	LANGUAGE C STRICT;

	CREATE OR REPLACE FUNCTION
		mask_activity()
	RETURNS
		void
	AS 
		'/usr/lib64/data_encryption.so','mask_activity'
	LANGUAGE C STABLE STRICT;

/* define index operator */
	/* for encrypted text */
	CREATE OPERATOR = (
	leftarg = encrypt_text, rightarg = encrypt_text, procedure = enc_compeq_enctext, restrict = eqsel, join = eqjoinsel );
	/* for encrypted binary */
	CREATE OPERATOR = (
	leftarg = encrypt_bytea, rightarg = encrypt_bytea, procedure = enc_compeq_encbytea, restrict = eqsel, join = eqjoinsel );

/* define index for encrypted type column */
	/* define hash index for encrypted text */
	CREATE OPERATOR CLASS
		hashtext_enc_ops
	DEFAULT FOR TYPE
		encrypt_text
	USING
		hash
	AS
		OPERATOR		1	   = (encrypt_text,encrypt_text),
		FUNCTION		1	   enc_hash_enctext(encrypt_text);

	/* define hash index for encrypted binary */
	CREATE OPERATOR CLASS
		hashbytea_enc_ops
	DEFAULT FOR TYPE
		encrypt_bytea
	USING
		hash
	AS
		OPERATOR 		1	   = (encrypt_bytea,encrypt_bytea),
		FUNCTION 		1	   enc_hash_encbytea(encrypt_bytea);

/* define cast function for encrypted type column */
	CREATE OR REPLACE FUNCTION
		enctext(boolean)
	RETURNS
		encrypt_text
	AS
		'/usr/lib64/data_encryption.so','boolenctext'
	LANGUAGE C STRICT;

	CREATE OR REPLACE FUNCTION
		enctext(character)
	RETURNS
		encrypt_text
	AS
		'/usr/lib64/data_encryption.so','enctextrtrim'
	LANGUAGE C STABLE STRICT;

	CREATE OR REPLACE FUNCTION
		enctext(inet)
	RETURNS
		encrypt_text
	AS
		'/usr/lib64/data_encryption.so','inetenctext'
	LANGUAGE C STABLE STRICT;

	CREATE OR REPLACE FUNCTION
		enctext(xml)
	RETURNS
		encrypt_text
	AS
		'/usr/lib64/data_encryption.so','xmlenctext'
	LANGUAGE C STABLE STRICT;

	CREATE OR REPLACE FUNCTION
		regclass(encrypt_text)
	RETURNS
		regclass
	AS
		'/usr/lib64/data_encryption.so','enctext_regclass'
	LANGUAGE C STABLE STRICT;

	/* encrypted test -> text */
	CREATE CAST
		(encrypt_text AS text)
	WITH INOUT
	AS IMPLICIT;
	/* text -> encrypted text */
	CREATE CAST
		(text AS encrypt_text)
	WITH INOUT
	AS ASSIGNMENT;
	/* boolean -> encrypted text */
	CREATE CAST
		(boolean AS encrypt_text)
	WITH FUNCTION enctext(boolean)
	AS ASSIGNMENT;
	/* character -> encrypted text */
	CREATE CAST
		(character AS encrypt_text)
	WITH FUNCTION enctext(character)
	AS ASSIGNMENT;
	/* cidr -> encrypted text */
	CREATE CAST
		(cidr AS encrypt_text)
	WITH FUNCTION enctext(inet)
	AS ASSIGNMENT;
	/* inet -> encrypted text */
	CREATE CAST
		(inet AS encrypt_text)
	WITH FUNCTION enctext(inet)
	AS ASSIGNMENT;
	/* xml -> encrypted text */
	CREATE CAST
		(xml AS encrypt_text)
	WITH FUNCTION enctext(xml)
	AS ASSIGNMENT;
	/* encrypted text -> regclass */
	CREATE CAST
		(encrypt_text AS regclass)
	WITH FUNCTION regclass(encrypt_text)
	AS ASSIGNMENT;

	/* binary -> encrypted binary */
	CREATE CAST
		(encrypt_bytea AS bytea)
	WITH INOUT
	AS IMPLICIT;
	/* encrypted binary -> binary */
	CREATE CAST
		(bytea AS encrypt_bytea)
	WITH INOUT
	AS ASSIGNMENT;

/* define table for managing encryption key */
	DROP TABLE IF EXISTS cipher_key_table;
	CREATE TABLE cipher_key_table (key BYTEA
								, algorithm TEXT);
