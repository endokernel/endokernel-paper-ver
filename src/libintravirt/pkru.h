#ifndef _PKRU_H_

#define PKRU_AD_BIT 1ul
#define PKRU_WD_BIT 2ul
#define PKRU_BITS_PER_PKEY 2
#define PKRU_MAX 15
#define PKRU_AD_KEY(pkey)	(PKRU_AD_BIT << ((pkey) * PKRU_BITS_PER_PKEY))
#define PKRU_WD_KEY(pkey)	(PKRU_WD_BIT << ((pkey) * PKRU_BITS_PER_PKEY))
#define PKRU_NO_KEY(pkey)   ((PKRU_AD_BIT|PKRU_WD_BIT) << ((pkey) * PKRU_BITS_PER_PKEY))
#define PKRU_AL_KEY(pkey)   0
#define PKEY_KEY(pkru, pkey) ((((pkru) >> ((pkey) *  PKRU_BITS_PER_PKEY)) & 3) ^ 3)
// domain 0 - less critical domain, readable from user
// domain 1 - highly secure domain, not readable and not writable
// domain 2 - untrusted default domain
#define IV_NORMAL 0
#define IV_CONF 1
#define IV_USER 2
#define IV_TEMP 15
// normal temp pages are put inside IV_TEMP
// when enter certain temp domain, it gets
// moved to current domain id

#define IV_TEMPMAN 14 
#define IV_TEMP_ALLOW 13 // move mem to this domain so everyone can access
#define untrusted_pkru (PKRU_WD_KEY( 0) | PKRU_NO_KEY( 1) | PKRU_AL_KEY( 2) | \
  PKRU_NO_KEY( 3) | PKRU_NO_KEY( 4) | PKRU_NO_KEY( 5) | \
  PKRU_NO_KEY( 6) | PKRU_NO_KEY( 7) | PKRU_NO_KEY( 8) | \
  PKRU_NO_KEY( 9) | PKRU_NO_KEY(10) | PKRU_NO_KEY(11) | \
  PKRU_NO_KEY(12) | PKRU_AL_KEY(13) | PKRU_WD_KEY(14) | \
  PKRU_AL_KEY(15))  

// a untrusted_pkru = {untrusted, *}, so domain 15 = ALL

#define unsafe_pkru (PKRU_WD_KEY( 0) | PKRU_NO_KEY( 1) | PKRU_NO_KEY( 2) | PKRU_NO_KEY( 3) |  \
  PKRU_NO_KEY( 4) | PKRU_NO_KEY( 5) | PKRU_NO_KEY( 6) |  \
  PKRU_NO_KEY( 7) | PKRU_NO_KEY( 8) | PKRU_NO_KEY( 9) |  \
  PKRU_NO_KEY(10) | PKRU_NO_KEY(11) | PKRU_NO_KEY(12) |  \
  PKRU_WD_KEY(13) | PKRU_WD_KEY(14) | PKRU_NO_KEY(15))  

#define notemp_pkru (PKRU_NO_KEY(IV_TEMP))

#define min_safebox 3
#define max_safebox 8
#define min_sandbox 9
#define max_sandbox 12

#define trusted_pkru (PKRU_AL_KEY(15))

#define safebox_pkru(n) ((untrusted_pkru) & ~PKRU_NO_KEY(n))
#define sandbox_pkru(n) ((unsafe_pkru) & ~PKRU_NO_KEY(n))

#define temp_pkru (PKRU_WD_KEY( 0) | PKRU_NO_KEY( 1) | PKRU_AL_KEY( 2) | \
  PKRU_AL_KEY( 3) | PKRU_AL_KEY( 4) | PKRU_AL_KEY( 5) | \
  PKRU_AL_KEY( 6) | PKRU_AL_KEY( 7) | PKRU_AL_KEY( 8) | \
  PKRU_AL_KEY( 9) | PKRU_AL_KEY(10) | PKRU_AL_KEY(11) | \
  PKRU_AL_KEY(12) | PKRU_AL_KEY(13) | PKRU_AL_KEY(14) | \
  PKRU_AL_KEY(15))  

#endif
