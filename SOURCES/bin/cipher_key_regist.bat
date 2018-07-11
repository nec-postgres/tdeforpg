echo off
START powershell -WindowStyle Hidden "& '%~dp0\cipher_key_regist.ps1' %*"
exit 0