SET search_path TO public;
SET check_function_bodies TO off;


/*------------------------------------------------------------*
 * Function : pgtde_begin_session
  * 
 * @param TEXT $1	do not used
 * @return result of load encryption key table to memory
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION pgtde_begin_session (TEXT) RETURNS BOOLEAN AS $$

BEGIN
	RETURN TRUE;
END;
$$ LANGUAGE plpgsql;


/*------------------------------------------------------------*
 * Function : pgtde_end_session
 * 
 * restore search path
 * 
 * @return true when encryption is not used
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION pgtde_end_session () RETURNS BOOLEAN AS $$

BEGIN
	RETURN TRUE;
END;
$$ LANGUAGE plpgsql;
