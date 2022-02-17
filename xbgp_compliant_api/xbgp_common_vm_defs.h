//
// Created by thomas on 6/12/21.
//

#ifndef XBGP_PLUGINS_XBGP_COMMON_VM_DEFS_H
#define XBGP_PLUGINS_XBGP_COMMON_VM_DEFS_H

#include <stdint.h>

#define UTILITY_PP_CONCAT_(v1, v2) v1 ## v2
#define UTILITY_PP_CONCAT(v1, v2) UTILITY_PP_CONCAT_(v1, v2)

#define UTILITY_PP_CONCAT5_(_0, _1, _2, _3, _4) _0 ## _1 ## _2 ## _3 ## _4

#define UTILITY_PP_IDENTITY_(x) x
#define UTILITY_PP_IDENTITY(x) UTILITY_PP_IDENTITY_(x)

#define UTILITY_PP_VA_ARGS_(...) __VA_ARGS__
#define UTILITY_PP_VA_ARGS(...) UTILITY_PP_VA_ARGS_(__VA_ARGS__)

#define UTILITY_PP_IDENTITY_VA_ARGS_(x, ...) x, __VA_ARGS__
#define UTILITY_PP_IDENTITY_VA_ARGS(x, ...) UTILITY_PP_IDENTITY_VA_ARGS_(x, __VA_ARGS__)

#define UTILITY_PP_IIF_0(x, ...) __VA_ARGS__
#define UTILITY_PP_IIF_1(x, ...) x
#define UTILITY_PP_IIF(c) UTILITY_PP_CONCAT_(UTILITY_PP_IIF_, c)

#define UTILITY_PP_HAS_COMMA(...) UTILITY_PP_IDENTITY(UTILITY_PP_VA_ARGS_TAIL(__VA_ARGS__, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0))
#define UTILITY_PP_IS_EMPTY_TRIGGER_PARENTHESIS_(...) ,

#define UTILITY_PP_IS_EMPTY(...) UTILITY_PP_IS_EMPTY_( \
    /* test if there is just one argument, eventually an empty one */ \
    UTILITY_PP_HAS_COMMA(__VA_ARGS__),                                \
    /* test if _TRIGGER_PARENTHESIS_ together with the argument adds a comma */ \
    UTILITY_PP_HAS_COMMA(UTILITY_PP_IS_EMPTY_TRIGGER_PARENTHESIS_ __VA_ARGS__), \
    /* test if the argument together with a parenthesis adds a comma */ \
    UTILITY_PP_HAS_COMMA(__VA_ARGS__ ()),                             \
    /* test if placing it between _TRIGGER_PARENTHESIS_ and the parenthesis adds a comma */ \
    UTILITY_PP_HAS_COMMA(UTILITY_PP_IS_EMPTY_TRIGGER_PARENTHESIS_ __VA_ARGS__ ()))

#define UTILITY_PP_IS_EMPTY_(_0, _1, _2, _3) UTILITY_PP_HAS_COMMA(UTILITY_PP_CONCAT5_(UTILITY_PP_IS_EMPTY_IS_EMPTY_CASE_, _0, _1, _2, _3))
#define UTILITY_PP_IS_EMPTY_IS_EMPTY_CASE_0001 ,

#define UTILITY_PP_VA_ARGS_SIZE(...) UTILITY_PP_IIF(UTILITY_PP_IS_EMPTY(__VA_ARGS__))(0, UTILITY_PP_VA_ARGS_SIZE_(__VA_ARGS__, UTILITY_PP_VA_ARGS_SEQ64()))
#define UTILITY_PP_VA_ARGS_SIZE_(...) UTILITY_PP_IDENTITY(UTILITY_PP_VA_ARGS_TAIL(__VA_ARGS__))

#define UTILITY_PP_VA_ARGS_TAIL(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, x, ...) x
#define UTILITY_PP_VA_ARGS_SEQ64() 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0


#define NUMARGS_SPRINTF__(...)  (UTILITY_PP_VA_ARGS_SIZE(__VA_ARGS__))

/* used to pass variadic arguments (e.g. sprintf, log, printf) */
struct vtype {
    int type;
    union {
        int8_t s8;
        uint8_t u8;
        int16_t s16;
        uint16_t u16;
        int32_t s32;
        uint32_t u32;
        int64_t s64;
        uint64_t u64;
        float fvalue;
        double dvalue;
        long double ldvalue;
        void *pvalue;

        unsigned char uchar;
        char schar;
        unsigned short ushort;
        short sshort;
        unsigned int uint;
        int sint;
        unsigned long ulong;
        long slong;
        unsigned long long ullong;
        long long sllong;
    } val;
};

struct vargs {
    int nb_args;
    struct vtype *args;
};

enum {
    VT_S8, VT_U8,
    VT_S16, VT_U16,
    VT_S32, VT_U32,
    VT_S64, VT_U64,
    VT_FLOAT, VT_DOUBLE, VT_LONGDOUBLE,
    VT_POINTER,
    VT_UCHAR, VT_SCHAR,
    VT_USHORT, VT_SSHORT,
    VT_UINT, VT_SINT,
    VT_SLONG, VT_ULONG,
    VT_ULLONG, VT_SLLONG
};


#define NUMARGS_LOGMSG(...) (UTILITY_PP_VA_ARGS_SIZE(__VA_ARGS__))

#define LOG_S8(i) ((struct vtype) {.val = {.s8 = (i)}, .type = VT_S8})
#define LOG_U8(i) ((struct vtype) {.val = {.u8 = (i)}, .type = VT_U8})
#define LOG_S16(i) ((struct vtype) {.val = {.s16 = (i)}, .type = VT_S16})
#define LOG_U16(i) ((struct vtype) {.val = {.u16 = (i)}, .type = VT_U16})
#define LOG_S32(i) ((struct vtype) {.val = {.s32 = (i)}, .type = VT_S32})
#define LOG_U32(i) ((struct vtype) {.val = {.u32 = (i)}, .type = VT_U32})
#define LOG_S64(i) ((struct vtype) {.val = {.s64 = (i)}, .type = VT_S64})
#define LOG_U64(i) ((struct vtype) {.val = {.u64 = (i)}, .type = VT_U64})
#define LOG_FLOAT(i) ((struct vtype) {.val = {.fvalue = (i)}, .type = VT_FLOAT})
#define LOG_DOUBLE(i) ((struct vtype) {.val = {.dvalue = (i)}, .type = VT_DOUBLE})
#define LOG_LDOUBLE(i) ((struct vtype) {.val = {.ldvalue = (i)}, .type = VT_LONGDOUBLE})
#define LOG_PTR(i) ((struct vtype) {.val = {.pvalue = (void *)(i)}, .type = VT_POINTER})
#define LOG_STR(i) LOG_PTR(i)
#define LOG_SCHAR(i) ((struct vtype) {.val = {.schar = (i)}, .type = VT_SCHAR})
#define LOG_UCHAR(i) ((struct vtype) {.val = {.uchar = (i)}, .type = VT_UCHAR})
#define LOG_SSHORT(i) ((struct vtype) {.val = {.sshort = (i)}, .type = VT_SSHORT})
#define LOG_USHORT(i) ((struct vtype) {.val = {.ushort = (i)}, .type = VT_USHORT})
#define LOG_INT(i) ((struct vtype) {.val = {.sint = (i)}, .type = VT_SINT})
#define LOG_UINT(i) ((struct vtype) {.val = {.uint = (i)}, .type = VT_UINT})
#define LOG_SLONG(i) ((struct vtype) {.val = {.slong = (i)}, .type = VT_SLONG})
#define LOG_ULONG(i) ((struct vtype) {.val = {.ulong = (i)}, .type = VT_ULONG})
#define LOG_SLLONG(i) ((struct vtype) {.val = {.sllong = (i)}, .type = VT_SLLONG})
#define LOG_ULLONG(i) ((struct vtype) {.val = {.ullong = (i)}, .type = VT_ULLONG})

#define L_DEBUG "\001"            /* Debugging messages */
#define L_TRACE "\002"            /* Protocol tracing */
#define L_INFO "\003"            /* Informational messages */
#define L_REMOTE "\004"            /* Remote protocol errors */
#define L_WARN "\005"            /* Local warnings */
#define L_ERR "\006"            /* Local errors */
#define L_AUTH "\007"            /* Authorization failed etc. */
#define L_FATAL "\010"            /* Fatal errors */
#define L_BUG "\011"            /* BIRD bugs */


typedef enum SOCKET_INTERFACE sk_type_t;

enum SOCKET_INTERFACE {
    PLUGIN_SOCKET_MIN,
    PLUGIN_SOCKET_QUIC,
    PLUGIN_SOCKET_TCP,
    PLUGIN_SOCKET_UDP,
    PLUGIN_SOCKET_MAX
};

struct global_info {
    void *hidden_ptr;
    int type;
};

/* hidden arguments of the insertion point,
 * to be retrieved with get_arg function */
typedef struct entry_arg entry_arg_t;

typedef struct {
    entry_arg_t *args;
    int nargs;
} args_t;

/* argument passed to the main function of the plugin */
typedef struct {
    int return_val_set;
    uint64_t replace_return_value;
    int insertion_point_id;
} exec_info_t;

enum RESERVED_RETURN_VAL {
    BPF_UNDEF = 0,
    BPF_CONTINUE, // continue the execution of the mode (ONLY in PRE or POST mode)
    BPF_FAILURE, // the uBPF code has badly terminated. On PRE and POST mode, continue the execution of other modes
    BPF_SUCCESS, // the uBPF code has successfully terminated. On PRE and POST, tells to the manager to return (other mode are skipped)
    BPF_MAX_RESERVED_RETURN_VAL
};

#endif //XBGP_PLUGINS_XBGP_COMMON_VM_DEFS_H
