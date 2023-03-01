@echo off
set projectname=pypykatz
set hiddenimports= --hidden-import cryptography --hidden-import cffi --hidden-import cryptography.hazmat.backends.openssl --hidden-import cryptography.hazmat.bindings._openssl --hidden-import unicrypto --hidden-import unicrypto.backends.pycryptodome.DES --hidden-import  unicrypto.backends.pycryptodome.TDES --hidden-import unicrypto.backends.pycryptodome.AES --hidden-import unicrypto.backends.pycryptodome.RC4 --hidden-import unicrypto.backends.pure.DES --hidden-import  unicrypto.backends.pure.TDES --hidden-import unicrypto.backends.pure.AES --hidden-import unicrypto.backends.pure.RC4 --hidden-import unicrypto.backends.cryptography.DES --hidden-import  unicrypto.backends.cryptography.TDES --hidden-import unicrypto.backends.cryptography.AES --hidden-import unicrypto.backends.cryptography.RC4 --hidden-import unicrypto.backends.pycryptodomex.DES --hidden-import  unicrypto.backends.pycryptodomex.TDES --hidden-import unicrypto.backends.pycryptodomex.AES --hidden-import unicrypto.backends.pycryptodomex.RC4
set root=%~dp0
set repo=%root%..\..\%projectname%
IF NOT DEFINED __BUILDALL_VENV__ (GOTO :CREATEVENV)
GOTO :BUILD

:CREATEVENV
python -m venv %root%\env
CALL %root%\env\Scripts\activate.bat
pip install pyinstaller
GOTO :BUILD

:BUILD
cd %repo%\..\
pip install .
cd %repo%
pyinstaller -F __main__.py %hiddenimports%
cd %repo%\dist & copy __main__.exe %root%\pypykatz.exe
GOTO :CLEANUP

:CLEANUP
IF NOT DEFINED __BUILDALL_VENV__ (deactivate)
cd %root%
EXIT /B
