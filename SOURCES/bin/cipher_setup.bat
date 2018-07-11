echo off
START powershell -WindowStyle Hidden "& '%~dp0\cipher_setup.ps1' %*"
exit 0