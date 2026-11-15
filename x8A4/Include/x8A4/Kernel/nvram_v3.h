//
// NonceSetX: persistent boot-nonce write through IONVRAMV3Handler::_varEntries.
//

#ifndef X8A4_NVRAM_V3_H
#define X8A4_NVRAM_V3_H

/* Prototypes */
int x8A4_v3_check(void);
int x8A4_v3_set_apnonce_generator(const char *generator);

#endif//X8A4_NVRAM_V3_H
