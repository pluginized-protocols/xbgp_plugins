//
// Created by thomas on 8/04/21.
//

#ifndef XBGP_PLUGINS_PROVE_H
#define XBGP_PLUGINS_PROVE_H

#define PROVERS
#define PROVERS_SEAHORN

#ifdef PROVERS
#include "mod_ubpf_api.c"
#endif

#ifdef PROVERS
#define next() return NEXT_RETURN_VALUE

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
#ifdef PROVERS_SEAHORN
  #include "seahorn/seahorn.h"
  #define p_assert(x) sassert(x)

  #include "../prove_stuffs/prove_helpers.h"
#else
  #ifdef PROVERS_CBMC
    #include <assert.h>
    #define p_assert(x) assert(x)
  #else
    #define p_assert(x)
  #endif
#endif

/*
 * Definition of macro to be used to add
 * instructions that will be added when the
 * macro definition is declared at compile
 * time
 */

#ifdef PROVERS
#define PROOF_INSTS(...) __VA_ARGS__
#else
#define PROOF_INSTS(...)
#endif

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
#else
#define PROOF_T2_INSTS(...)
#endif

#endif //XBGP_PLUGINS_PROVE_H
