#include <stdbool.h>

extern bool CreateSEP256Key(char *buffer, int *length);
extern bool GetSEP256PublicKey(char *privateKey, int privateKeyLength, char *buffer, int *length);
extern bool SEP256KeyAgreement(char *privateKey, int privateKeyLength, char *publicKey, int publicKeyLength, char *buffer, int *length);
