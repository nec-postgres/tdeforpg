SET search_path TO public;
SET check_function_bodies TO off;

/*------------------------------------------------------------*
 * Function : cipher_key_regist
 *
 * add new key to the encryption key table
 * 
 * @param TEXT $1	current encryption key
 * @param TEXT $2	new encryption key
 * @param TEXT $3	encryption algorithm
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION cipher_key_regist (TEXT, TEXT, TEXT) RETURNS INTEGER AS $$

DECLARE
	current_cipher_key  ALIAS FOR $1;
	cipher_key  ALIAS FOR $2;
	cipher_algorithm ALIAS FOR $3;

	current_cipher_algorithm TEXT;
	
	f_key_num SMALLINT;			/* number of encryption key*/

BEGIN
	/* mask pg_stat_activity's query */
	PERFORM mask_activity();

	/* if cipher_key_disable_log is not yet executed, output an error */
	IF (SELECT setting FROM pg_settings WHERE name = 'encrypt.mask_cipherkeylog') != 'on' THEN
		RAISE EXCEPTION 'TDE-E0036 you must call cipher_key_disable_log function first[02].';
	END IF;

	IF cipher_key IS NULL OR cipher_key = '' THEN
		RAISE EXCEPTION 'TDE-E0002 new cipher key is invalid[01]';
	END IF;

	/* validate encryption algorithm */
	IF cipher_algorithm != 'aes' AND cipher_algorithm != 'bf' THEN
		RAISE EXCEPTION 'TDE-E0003 invalid cipher algorithm "%"[01]', cipher_algorithm;
	END IF;

	SET LOCAL search_path TO public;
	SET LOCAL enable_seqscan TO off;

	/* obtain lock of enryption key table */
	LOCK TABLE cipher_key_table IN EXCLUSIVE MODE;

	/* getting the number of encryption key */
	SELECT count(*) INTO f_key_num FROM cipher_key_table;
	/* if encryption key is already exist */
	IF f_key_num = 1 THEN
		IF current_cipher_key IS NULL THEN
			RAISE EXCEPTION 'TDE-E0008 current cipher key is not correct[01]';
		END IF;
		/* if current key is valid and save current encryption algorithm*/
		BEGIN
			SELECT algorithm INTO current_cipher_algorithm FROM cipher_key_table WHERE pgp_sym_decrypt(key, current_cipher_key)=current_cipher_key;
		EXCEPTION
			WHEN SQLSTATE '39000' THEN
				RAISE EXCEPTION 'TDE-E0008 current cipher key is not correct[01]';
		END;
		/* delete current key */
		DELETE FROM cipher_key_table;

	/* too many key is exists */
	ELSEIF f_key_num > 1 THEN
			RAISE EXCEPTION 'TDE-E0009 too many encryption keys are exists in cipher_key_table[01]';
	END IF;
	
	/* encrypt and register new key */
	INSERT INTO cipher_key_table(key, algorithm) VALUES(pgp_sym_encrypt(cipher_key, cipher_key, 'cipher-algo=aes256, s2k-mode=1'), cipher_algorithm);
	
	/* backup encryption key table */
	PERFORM cipher_key_backup();
	/* reencrypt all data */
	IF f_key_num = 1 THEN
		PERFORM cipher_key_reencrypt_data(current_cipher_key, current_cipher_algorithm, cipher_key);
	END IF;

	/* return 1 */
	RETURN 1;
END;
$$ LANGUAGE plpgsql;


/*------------------------------------------------------------*
 * Function : cipher_key_reencrypt_data
 * 
 * re-encrypt specified data periodically using encryption key 
 * which is specified custom parameter
 * 
 * @return true if re-encryption is successfully done
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION cipher_key_reencrypt_data (TEXT, TEXT, TEXT) RETURNS BOOLEAN AS $$

DECLARE

	old_cipher_key ALIAS FOR $1;
	old_cipher_algorithm ALIAS FOR $2;
	new_cipher_key  ALIAS FOR $3;

	f_rec RECORD;	/* store target update column */
	f_rec2 RECORD;	/* store target update row */
	f_cu	REFCURSOR;	/* fetch target update column */
	f_cu2	REFCURSOR;	/* fetch target update row */

	f_counter	BIGINT;		/* number of processed target record*/
	f_result	BIGINT;

	f_query TEXT;					/* store dynamic SQL string */
	
	f_relid BIGINT;
	f_nspname TEXT;
	f_relname TEXT;
	f_islast BOOLEAN;

BEGIN
	/* init */
	f_counter := 0;
	f_relid := 0;
	f_nspname = '';
	f_relname = '';
	f_islast = FALSE;

	SET LOCAL search_path TO public;
	SET LOCAL encrypt.enable TO on;
	SET LOCAL encrypt.noversionerror TO on;
	
	/* set new key to memory */
	PERFORM pgtde_begin_session(new_cipher_key);
	/* set old key to memory */
	PERFORM enc_store_old_key_info(old_cipher_key, old_cipher_algorithm);

	/* store column of user defined table */
	OPEN
		f_cu
	FOR
		SELECT a.attrelid, n.nspname, c.relname, a.attname, t.typname
		FROM pg_attribute a, pg_class c, pg_type t, pg_namespace n
		WHERE a.attrelid = c.oid
		AND t.oid = a.atttypid
		AND c.relnamespace = n.oid
		AND c.relkind = 'r'
		AND t.typname IN ('encrypt_text', 'encrypt_bytea')
		AND n.nspname != 'information_schema'
		AND n.nspname NOT LIKE E'pg\\_%'
		ORDER BY nspname, relname, attname;
	

	/* re-encryption */
	FETCH f_cu INTO f_rec;
	IF NOT FOUND THEN
		f_islast := TRUE;
	END IF;

	/* update each encrypted column */
	LOOP
		IF f_islast THEN
			EXIT;
		END IF;

		f_relid := f_rec.attrelid;
		f_nspname := f_rec.nspname;
		f_relname := f_rec.relname;

		f_query := 'UPDATE ONLY ' || quote_ident(f_rec.nspname) || '.' || quote_ident(f_rec.relname) || ' SET ';

		LOOP
			IF f_rec.typname = 'encrypt_text' THEN
				f_query := f_query || quote_ident(f_rec.attname) || ' = ' || quote_ident(f_rec.attname) || '::text::encrypt_text ';
			ELSE
				f_query := f_query || quote_ident(f_rec.attname) || ' = ' || quote_ident(f_rec.attname) || '::bytea::encrypt_bytea ';
			END IF;

			FETCH f_cu INTO f_rec;
			IF NOT FOUND THEN
				f_islast := TRUE;
			END IF;

			IF f_islast OR f_relid != f_rec.attrelid THEN
				f_query := f_query || ';';
				EXIT;
			ELSE
				f_query := f_query || ', ';
			END IF;
		END LOOP;

		RAISE INFO 'TDE-I0001 re-encryption of table "%"."%" was started[01]', f_nspname, f_relname;

		EXECUTE f_query;

		RAISE INFO 'TDE-I0002 re-encryption of table "%"."%" was completed[01]', f_nspname, f_relname;
	END LOOP;

	CLOSE f_cu;
	
	/* delete old key from memory */
	PERFORM enc_drop_old_key_info();
	/* drop key from memory */
	PERFORM pgtde_end_session();

	RETURN TRUE;
END;
$$ LANGUAGE plpgsql;


/*------------------------------------------------------------*
 * Function : cipher_key_backup
 *
 * backup encryption key table
 * if backup already exists, rename backup to <filename>.sv
 * and backup current key table
 * 
 * @return true, if 
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION cipher_key_backup () RETURNS BOOLEAN AS $$

DECLARE
	f_filepath TEXT;	/* path of backupfile */
	f_old_filepath TEXT;	/* old backupfile */
	f_query TEXT;		/* dynamic SQL */
	f_dbname TEXT;		/* current dbname */
	result BOOLEAN;

BEGIN
	/* get path of backup file from encrypt.backup */
	SELECT setting INTO f_filepath FROM pg_settings WHERE name = 'encrypt.backup';

	/* if encrypt.backup is not set, get value of data_directory */
	IF(f_filepath = '')THEN
		SELECT setting INTO f_filepath FROM pg_settings WHERE name = 'data_directory';

		IF f_filepath IS NULL THEN
			RAISE EXCEPTION 'TDE-E0014 could not get data directory path[01]';
		END IF;
	END IF;

	/* get name of current db */
	SELECT current_database() INTO f_dbname;

	/* set filename of backup */
	f_filepath := f_filepath || E'/ck_backup_' || f_dbname;
	f_old_filepath := f_filepath || E'.sv';

	/* rename if "ck_backup" is already exists */
	SELECT enc_rename_backupfile(f_filepath, f_old_filepath) INTO result;

	IF result = FALSE THEN
		RAISE EXCEPTION 'TDE-E0015 could not rename old backup file of cipher key[01]';
	END IF;

	/* backup current encryption key table */
	f_query := 'COPY cipher_key_table TO ''' || f_filepath || '''';
	EXECUTE f_query;

	RETURN result;
END;
$$ LANGUAGE plpgsql
SET search_path TO public;


/*------------------------------------------------------------*
 * Function : cipher_key_disable_log
 * 
 * set track_activities to off and encrypt.mask_cipherkeylog to on.
 * In order to remove cipher info in pg_stat_activity's query.
 * 
 * @return TRUE
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION cipher_key_disable_log () RETURNS BOOLEAN AS $$

DECLARE
	save_result BOOLEAN;	/* result of backup current parameter */

BEGIN

	SET track_activities = off;
	SET encrypt.mask_cipherkeylog = on;
	RETURN TRUE;

END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO public;


/*------------------------------------------------------------*
 * Function : cipher_key_enable_log
 *
 * set back track_activities to default and encrypt.mask_cipherkeylog to off.
 * 
 * @return TRUE
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION cipher_key_enable_log () RETURNS BOOLEAN AS $$

DECLARE
	save_result BOOLEAN;

BEGIN

	SET track_activities = DEFAULT;
	SET encrypt.mask_cipherkeylog = off;
	RETURN TRUE;

END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO public;

/*------------------------------------------------------------*
 * Function : pgtde_version()
 *
 * return current TDE version.
 * 
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION pgtde_version() RETURNS TEXT AS $$
BEGIN
	RETURN 'Free Edition 1.1.1.1';
END;
$$ LANGUAGE plpgsql;

