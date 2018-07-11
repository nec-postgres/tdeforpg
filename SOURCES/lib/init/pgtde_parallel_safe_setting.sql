
--- add parallel unsafe for PostgreSQL greater than 9.6 ---
--- TDEforPG does not support Parallel Query Feature. ---

--------------------------------------------------------------------------------------
---------------------------------- pgcrypto sql function -----------------------------
--------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------
-------------------------------------- parallel unsafe function ----------------------
--------------------------------------------------------------------------------------
ALTER FUNCTION decrypt                      	( bytea, bytea, text                             ) PARALLEL UNSAFE;
ALTER FUNCTION encrypt                      	( bytea, bytea, text                             ) PARALLEL UNSAFE;
ALTER FUNCTION pgp_sym_decrypt              	( bytea, text                                    ) PARALLEL UNSAFE;
ALTER FUNCTION pgp_sym_decrypt              	( bytea, text, text                              ) PARALLEL UNSAFE;
ALTER FUNCTION pgp_sym_encrypt              	( text, text                                     ) PARALLEL UNSAFE;
ALTER FUNCTION pgp_sym_encrypt              	( text, text, text                               ) PARALLEL UNSAFE;
--------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------
---------------------------------- TDEforPG defined function -------------------------
--------------------------------------------------------------------------------------
-- Default of create function is parallel unsafe. All of TDEforPG's functions are 
-- PARALLEL UNSAFE. So it is necessary to ALTER them here. 


