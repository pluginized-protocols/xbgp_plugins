//
// Created by thomas on 14/01/22.
//

#ifndef XBGP_PLUGINS_XBGP_API_FUNCTION_HELPER_H
#define XBGP_PLUGINS_XBGP_API_FUNCTION_HELPER_H

#include <ffi.h>

typedef struct proto_ext_fun {
    void *fn;
    void (*closure_fn) (ffi_cif *, void *ret, void **args, void *ctx);
    const char *name;
    int attributes;

    int args_nb;
    ffi_type *return_type;
    ffi_type **args_type;

} proto_ext_fun_t;

typedef struct insertion_point_info {
    const char *insertion_point_str;
    int insertion_point_id;
} insertion_point_info_t;

#define insertion_point_info_null {.insertion_point_str = NULL, .insertion_point_id = 0}

#define proto_ext_func_null {.fn = NULL, .name = NULL, .attributes = 0, \
                             .args_type = NULL, .return_type = NULL, \
                             .args_nb = 0, .closure_fn = NULL }

#define proto_ext_func_is_null(a) (((a)->fn == NULL) &&       \
             ((a)->name == NULL) && ((a)->attributes == 0) &&     \
             ((a)->args_nb == 0) && ((a)->args_type == NULL) &&         \
             ((a)->return_type == NULL) && ((a)->closure_fn == NULL))

#define is_insertion_point_info_null(info) (((info)->insertion_point_str == NULL) && ((info)->insertion_point_id == 0))

#define XBGP_ARGS args

#define xbgp_api_name_closure(name) closure_##name

#define xbgp_def_fun_api(name, ret_val_type, ...) \
void xbgp_api_name_closure(name)(ffi_cif *cif UNUSED, void *ret, void **XBGP_ARGS, void *usr_data) { \
    ((void) XBGP_ARGS);                                         \
    ret_val_type ret_val;          \
    context_t *ctx = usr_data;\
    ret_val = name(ctx,##__VA_ARGS__);          \
    *(ret_val_type *) ret = ret_val; \
}

#define xbgp_def_fun_api_void(name, ...) \
void xbgp_api_name_closure(name)(ffi_cif *cif UNUSED, void *ret UNUSED, void **XBGP_ARGS, void *usr_data) { \
    ((void) XBGP_ARGS);  /* make compiler silent */                               \
    context_t *ctx = usr_data;\
    name(ctx,##__VA_ARGS__);   \
}


#endif //XBGP_PLUGINS_XBGP_API_FUNCTION_HELPER_H
