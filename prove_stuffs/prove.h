//
// Created by thomas on 8/04/21.
//

#ifndef XBGP_PLUGINS_PROVE_H
#define XBGP_PLUGINS_PROVE_H

#include "prove_helpers.h"

#ifdef PROVERS
#include "mod_ubpf_api.c"
#endif

#ifdef PROVERS
#ifdef PROVERS_ARG
#define next() \
checked = 0;   \
return NEXT_RETURN_VALUE
#else
#define next() return NEXT_RETURN_VALUE
#endif
#endif

#ifdef PROVERS_CBMC

char *strncpy(char *dest, const char *src, size_t n)  {
    size_t i;

    for (i = 0; i < n && src[i] != '\0'; i++)
        dest[i] = src[i];

    if (i < n)
        dest[i] = '\0';

    return dest;
}

#endif

/*
 * Define ASSERT statement
 * T2 does not support assertions
 */
#ifdef PROVERS_CBMC
  #include <assert.h>
  #define CBMC_assert(x) assert(x)
#else
  #define CBMC_assert(...)
#endif

#ifdef PROVERS_SEAHORN
  #include "seahorn/seahorn.h"
  #define p_assert(x) sassert(x)
  #define p_assume(x)

  #include "../prove_stuffs/prove_helpers.h"
#else
  #define p_assert(x)
  #define p_assume(x)
#endif

/*
 * Definition of macro to be used to add
 * instructions that will be added when the
 * macro definition is declared at compile
 * time
 */

#ifndef PROVERS_T2
    #ifdef PROVERS
        #define PROOF_INSTS(...) __VA_ARGS__
    #else
        #define PROOF_INSTS(...)
    #endif
#else
    #define PROOF_INSTS(...)
#endif

/*
#ifdef PROVERS
#define PROOF_INSTS(...) __VA_ARGS__
#else
#define PROOF_INSTS(...)
#endif
*/

#ifdef PROVERS_SEAHORN
#define PROOF_SEAHORN_INSTS(...) __VA_ARGS__
#else
#define PROOF_SEAHORN_INSTS(...)
#endif

#ifdef PROVERS_CBMC
#define PROOF_CBMC_INSTS(...) __VA_ARGS__
#else
#define PROOF_CBMC_INSTS(...)
#endif

#ifdef PROVERS_T2
#define PROOF_T2_INSTS(...) __VA_ARGS__
#define NOT_T2(...)
#define T2SI
#else
#define PROOF_T2_INSTS(...)
#define NOT_T2(...) __VA_ARGS__
#define T2SI static __inline __attribute__ ((__always_inline__))
#endif

#endif //XBGP_PLUGINS_PROVE_H
