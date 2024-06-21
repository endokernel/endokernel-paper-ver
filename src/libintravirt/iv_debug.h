#ifndef IV_DEBUG_H_

#define IV_DEBUG_H_

//#define IV_DEBUG

/* 
 * Debug prtins
 */
#ifdef IV_DEBUG
#define IV_DBG(x, ...)\
    printf("[IV_DBG] %s\t" x "\n", __FUNCTION__, ##__VA_ARGS__);
#else //disable debug
#define IV_DBG(x, ...) 
#endif


#endif
