//
// Created by thomas on 8/04/21.
//

#ifndef XBGP_PLUGINS_PROVE_H
#define XBGP_PLUGINS_PROVE_H


#ifdef PROVERS_SH
  #include "seahorn/seahorn.h"
  #define assert(x) sassert(x)

  #include "../prove_stuffs/prove_helpers.h"
  #define p_assert(x) assert(x)
#else
  #ifdef ASSERT_CBMC
    #include <assert.h>
    #define p_assert(x)
  #else
    #define p_assert(x)
  #endif
#endif

#endif //XBGP_PLUGINS_PROVE_H
