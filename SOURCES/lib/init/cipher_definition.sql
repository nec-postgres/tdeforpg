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
	DROP TYPE IF EXISTS encrypt_text CASCADE;
	DROP TYPE IF EXISTS encrypt_bytea CASCADE;

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
	LANGUAGE C STRICT;

	/* define output function of encrypted text type */
	CREATE FUNCTION
		enctext_out(encrypt_text)
	RETURNS
		cstring
	AS
		'/usr/lib64/data_encryption.so','enctext_out'
	LANGUAGE C IMMUTABLE STRICT;

	/* define recv function of encrypted text type */
	CREATE FUNCTION 
		enctext_recv(internal)
	RETURNS
		encrypt_text
	AS
		'/usr/lib64/data_encryption.so','encrecv'
	LANGUAGE C STRICT;

	/* define send function of encrypted text type */
	CREATE FUNCTION 
		enctext_send(encrypt_text)
	RETURNS
		bytea
	AS
		'/usr/lib64/data_encryption.so','encsend'
	LANGUAGE C STRICT;

	/* define input function of encrypted binary type */
	CREATE FUNCTION
		encbytea_in(cstring)
	RETURNS
		encrypt_bytea
	AS
		'/usr/lib64/data_encryption.so','encbytea_in'
	LANGUAGE C STRICT;

	/* define output function of encrypted binary type */
	CREATE FUNCTION
		encbytea_out(encrypt_bytea)
	RETURNS
		cstring
	AS
		'/usr/lib64/data_encryption.so','encbytea_out'
	LANGUAGE C IMMUTABLE STRICT;
	
	/* define recv function of encrypted binary type */
	CREATE FUNCTION 
		encbytea_recv(internal)
	RETURNS
		encrypt_bytea
	AS
		'/usr/lib64/data_encryption.so','encrecv'
	LANGUAGE C STRICT;

	/* define send function of encrypted binary type */
	CREATE FUNCTION 
		encbytea_send(encrypt_bytea)
	RETURNS
		bytea
	AS
		'/usr/lib64/data_encryption.so','encsend'
	LANGUAGE C STRICT;

	/* define encrypted text types */
	CREATE TYPE ENCRYPT_TEXT (
		INPUT = enctext_in
		, OUTPUT = enctext_out
		, RECEIVE = enctext_recv
		, SEND = enctext_send
		, INTERNALLENGTH = VARIABLE
		, ALIGNMENT = int4
		, STORAGE = extended);

	/* define encrypted binary types */
	CREATE TYPE ENCRYPT_BYTEA (
		INPUT = encbytea_in
		, OUTPUT = encbytea_out
		, RECEIVE = encbytea_recv
		, SEND = encbytea_send
		, INTERNALLENGTH = VARIABLE
		, ALIGNMENT = int4
		, STORAGE = extended);

	/* index operator of encrypted text types */
	CREATE OR REPLACE FUNCTION
		enc_compeq_enctext(encrypt_text,encrypt_text)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_compeq_enctext'
	LANGUAGE C STRICT;

	/* compare function of encrypted text type and text */
	CREATE OR REPLACE FUNCTION
		enc_compeq_text_enctext(text,encrypt_text)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_compeq_text_enctext'
	LANGUAGE C STRICT;
	CREATE OR REPLACE FUNCTION
		enc_compeq_enctext_text(encrypt_text,text)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_compeq_enctext_text'
	LANGUAGE C STRICT;

	/* index operator of encrypted binary types */
	CREATE OR REPLACE FUNCTION
		enc_compeq_encbytea(encrypt_bytea,encrypt_bytea)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_compeq_encbytea'
	LANGUAGE C STRICT;

	/* compare encrypted binary type and binary */
	CREATE OR REPLACE FUNCTION
		enc_compeq_bytea_encbytea(bytea,encrypt_bytea)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_compeq_bytea_encbytea'
	LANGUAGE C STRICT;
	CREATE OR REPLACE FUNCTION
		enc_compeq_encbytea_bytea(encrypt_bytea,bytea)
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_compeq_encbytea_bytea'
	LANGUAGE C STRICT;

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

	/* drops key informaiton from memory */
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

	/* backup current parameters of loglevel */
	CREATE OR REPLACE FUNCTION
		enc_save_logsetting()
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_save_logsetting'
	LANGUAGE C STRICT;

	/* restore log parameters from backup */
	CREATE OR REPLACE FUNCTION
		enc_restore_logsetting()
	RETURNS
		bool
	AS
		'/usr/lib64/data_encryption.so','enc_restore_logsetting'
	LANGUAGE C STRICT;

/* define index operator */
	/* for encrypted text */
	CREATE OPERATOR = (
	leftarg = encrypt_text, rightarg = encrypt_text, procedure = enc_compeq_enctext, restrict = eqsel, join = eqjoinsel );
	/* for encrypted binary */
	CREATE OPERATOR = (
	leftarg = encrypt_bytea, rightarg = encrypt_bytea, procedure = enc_compeq_encbytea, restrict = eqsel, join = eqjoinsel );

/* define index operator for encrypted type and plain type */
	/* text → encrypted text */
	CREATE OPERATOR = (
	leftarg = text, rightarg = encrypt_text, procedure = enc_compeq_text_enctext, commutator = =, restrict = eqsel, join = eqjoinsel );
	/* encrypted text → text */
	CREATE OPERATOR = (
	leftarg = encrypt_text, rightarg = text, procedure = enc_compeq_enctext_text, commutator = =, restrict = eqsel, join = eqjoinsel );
	/* binary → encrypted binary */
	CREATE OPERATOR = (
	leftarg = bytea, rightarg = encrypt_bytea, procedure = enc_compeq_bytea_encbytea, commutator = =, restrict = eqsel, join = eqjoinsel );
	/* encrypted binary → binary */
	CREATE OPERATOR = (
	leftarg = encrypt_bytea, rightarg = bytea, procedure = enc_compeq_encbytea_bytea, commutator = =, restrict = eqsel, join = eqjoinsel );

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
	/* encrypted test →  text */
	CREATE CAST
		(encrypt_text AS text)
	WITH INOUT
	AS IMPLICIT;
	/* text →  encrypted text */
	CREATE CAST
		(text AS encrypt_text)
	WITH INOUT
	AS IMPLICIT;

	/* binary →  encrypted binary */
	CREATE CAST
		(encrypt_bytea AS bytea)
	WITH INOUT
	AS IMPLICIT;
	/* encrypted binary →  binary */
	CREATE CAST
		(bytea AS encrypt_bytea)
	WITH INOUT
	AS IMPLICIT;

/* define table for managing encryption key */
	DROP TABLE IF EXISTS cipher_key_table;
	CREATE TABLE cipher_key_table (key BYTEA
								, algorithm TEXT);
