SET search_path TO public;
SET check_function_bodies TO off;

/*------------------------------------------------------------*
 * Function : pgtde_begin_session
 * 
 * load encryption key table to memory
 * exception will be raised in below cases
 * 1. value of log_statement is 'all'
 * 2. encryption key is invalid 
 * 
 * @param TEXT $1	lastest encryption key
 * @return result of load encryption key table to memory
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION pgtde_begin_session (TEXT) RETURNS BOOLEAN AS $$

DECLARE
	cipher_key ALIAS FOR $1;

	f_algorithm TEXT;		/* encryption algorithm of lastest key */
	f_key_num INTEGER;		/* number of encryption key */
	f_result BOOLEAN;

BEGIN
	/* mask pg_stat_activity's query */
	PERFORM mask_activity();

	/* if cipher_key_disable_log is not yet executed, output an error */
	IF (SELECT setting FROM pg_settings WHERE name = 'encrypt.mask_cipherkeylog') != 'on' THEN
		RAISE EXCEPTION 'TDE-E0036 you must call cipher_key_disable_log function first[01].';
	END IF;

	/* drop encryption key information in memory */
	PERFORM enc_drop_key_info();
	/* drop old-encryption key information in memory */
	PERFORM enc_drop_old_key_info();

	IF cipher_key IS NOT NULL THEN
		/* get number of registered encryption key */
		SELECT count(*) INTO f_key_num FROM cipher_key_table;

		/* return false, if there is no or too many encryption key */
		IF f_key_num = 0 THEN
			RETURN FALSE;
		ELSIF f_key_num>1 THEN
			RAISE EXCEPTION 'TDE-E0009 too many encryption keys are exists in cipher_key_table[02]';
		END IF;

		BEGIN
			/* load encryption key table to memory */
			PERFORM enc_store_key_info(pgp_sym_decrypt(key, cipher_key), algorithm)
			FROM (SELECT key, algorithm FROM cipher_key_table) AS ckt;
		EXCEPTION
			WHEN SQLSTATE '39000' THEN
				PERFORM enc_drop_key_info();
				RAISE EXCEPTION 'TDE-E0012 cipher key is not correct[01]';
		END;
	END IF;
	RETURN TRUE;
END;
$$ LANGUAGE plpgsql
SET search_path TO public;


/*------------------------------------------------------------*
 * Function : pgtde_end_session
 * 
 * drop encryption key table from memory
 * return false, if there is no encryption key table in memory
 * 
 * @return result of drop encryption key table in memory
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION pgtde_end_session () RETURNS BOOLEAN AS $$

BEGIN
	/* drop encryption key table in memory */
	IF (SELECT enc_drop_key_info()) THEN
		RETURN TRUE;
	ELSE
		RETURN FALSE;
	END IF;
END;
$$ LANGUAGE plpgsql
SET search_path TO public;
