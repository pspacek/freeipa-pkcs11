export PKCS11SPY=/usr/lib64/softhsm/libsofthsm2.so
pkcs11-tool --module /usr/lib64/pkcs11-spy.so --so-pin 1234 --new-pin 1234 -l --init-pin --slot 0 --label IPA --init-token
