//
// Created by thomas on 23/03/21.
//

// This file implements a fake API function call used to prove
// plugins.
// Functions of the xBGP API are not implemented here since
// it is dependant of the plugin being verified

// The implementation must be provided within the plugin itself

// Some functions such as get_arg are also not implemented
// as the return value also depends of the host implementation
// state and the insertion point

#include "mod_ubpf_api.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "../xbgp_compliant_api/xbgp_defs.h"
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <math.h>
#include <float.h>
#include <byteswap.h>

#define FAKE_POINTER ((void *) 0x1)
#define FAKE_CONTEXT FAKE_POINTER // we fake the context so that cbmc can walk to the non null branch


int super_log(const char *msg UNUSED, struct vargs *args UNUSED) {

    return 1;
}

clock_t bpf_clock() {
    return clock();
}

int get_time(struct timespec *spec) {
    return clock_gettime(CLOCK_MONOTONIC, spec);
}

#ifdef PROVERS_T2
#include <stdio.h>
#define ebpf_print(...)
#else
int ebpf_print_intern(const char *format, struct vargs *args) {
    printf(format, args->nb_args);
}
#endif

void *ebpf_memcpy(void *dst0, const void *src0, size_t length) {
    char *dest = dst0;
    char *dst = dst0;
    const char *src = src0;

    while (length > 0) {
        *dst++ = *src++;
        length = length == 0 ? 0 : length -1;
    }
    return dest;
}

int ebpf_memcmp(const void *s1, const void *s2, size_t n) {
    if (n != 0) {
        register const unsigned char *p1 = s1, *p2 = s2;

        do {
            if (*p1++ != *p2++)
                return (*--p1 - *--p2);
        } while (--n != 0);
    }
    return (0);
}

int numb(unsigned int nb, int base, char *buf, size_t len) {
    static const char *hexchars = "0123456789abcdef";
    char tmp[60];
    unsigned res;
    int j = 0, conv_len;

    while (nb != 0) {
        res = nb % base;
        nb = nb / base;
        tmp[j++] = hexchars[res];
    }

    conv_len = j;

    /* reverse tmp */
    while (j-- > 0 && len > 0) {
        *buf++ = tmp[j];
        len -= 1;
    }

    return conv_len;
}


#ifdef PROVERS_T2
/* T2 doesn't like ebpf_inet implementation */
int ebpf_inet_ntop(uint8_t *ipaddr, int type, char *buf, size_t len) {
    return 0;
}
#else
int ebpf_inet_ntop(uint8_t *ipaddr, int type, char *buf, size_t len) {
    static const char *hexchars = "0123456789abcdef";
    int i, j, k;

    unsigned hilo;
    unsigned lo;
    unsigned hi;

    if (!ipaddr) return 0;

    //uint8_t *ipaddr = ipaddr_;


    switch (type) {
        case AF_INET:
            for (i = 0, j = 0, k = 0; i < 4; i++) {
                j += numb(ipaddr[i], 10, buf + j, len - j);
                if (k < 3) {
                    buf[j++] = '.';
                    k++;
                }
            }
            buf[j] = 0;

            return 0;
        case AF_INET6:
            /* returns only the exploded form */
            for (i = 0, j = 0, k = 0; i < 16; i++) {
                hilo = ipaddr[i];
                lo = hilo & 0x0f;
                hi = hilo >> 4;

                buf[j++] = hexchars[hi];
                buf[j++] = hexchars[lo];
                if ((j - k) % 4 == 0 && k < 7) {
                    buf[j++] = ':';
                    k++;
                }
            }
            buf[j] = 0;

            return 0;
        default:
            return -1;
    }

    return 0;
}
#endif

#include "glib_c_inet_pton.c"

int ebpf_inet_pton(int af, const char *src, void *dst, size_t buf_len) {
    int s;
    size_t min_len;
    unsigned char buf[sizeof(struct in6_addr)];

    switch (af) {
        case AF_INET:
            min_len = sizeof(struct in_addr);
            break;
        case AF_INET6:
            min_len = sizeof(struct in6_addr);
            break;
        default:
            return -1;
    }

    if (buf_len < min_len) return -1;

    s = my_inet_pton(af, src, buf);

    if (s <= 0) {
        return -1;
    }
    memcpy(dst, buf, min_len);
    return 0;
}


#define ZEROPAD    1u        /* pad with zero */
#define SIGN    2u        /* unsigned/signed long */
#define PLUS    4u        /* show plus */
#define SPACE    8u        /* space if plus */
#define LEFT    16u        /* left justified */
#define SPECIAL    32u        /* 0x */
#define LARGE    64u        /* use 'ABCDEF' instead of 'abcdef' */

#define S_    * (uint64_t) 1000000
#define MS_    * (uint64_t) 1000
#define US_    * (uint64_t) 1
#define TO_S    /1000000
#define TO_MS    /1000
#define TO_US    /1

#define S    S_
#define MS    MS_
#define US    US_
#define NS    /1000

#define is_digit(c)    ((c) >= '0' && (c) <= '9')

static inline int skip_atoi(const char **s) {
    int i = 0;
#define MAX_REPR_UINT 10
    int iter = 0;

    while (is_digit(**s) && iter < MAX_REPR_UINT) {
        i = i * 10 + *((*s)++) - '0';
        iter++;
    }
    return i;
}

static inline char *
number(char *str, uint64_t num, uint base, int size, int precision, int type, int remains) {
    char c, sign, tmp[66];
    const char *digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    int i;

    if (size >= 0 && (remains -= size) < 0)
        return NULL;
    if (type & LARGE)
        digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (type & LEFT)
        type &= ~ZEROPAD;
    if (base < 2 || base > 36)
        return 0;
    c = (type & ZEROPAD) ? '0' : ' ';
    sign = 0;
    if (type & SIGN) {
        if (num > (uint64_t) INT64_MAX) {
            sign = '-';
            num = -num;
            size--;
        } else if (type & PLUS) {
            sign = '+';
            size--;
        } else if (type & SPACE) {
            sign = ' ';
            size--;
        }
    }
    if (type & SPECIAL) {
        if (base == 16)
            size -= 2;
        else if (base == 8)
            size--;
    }
    i = 0;
    if (num == 0)
        tmp[i++] = '0';
    else
        while (num != 0) {
            uint res = num % base;
            num = num / base;
            tmp[i++] = digits[res];
        }
    if (i > precision)
        precision = i;
    size -= precision;
    if (size < 0 && -size > remains)
        return NULL;
    if (!(type & (ZEROPAD + LEFT)))
        while (size-- > 0)
            *str++ = ' ';
    if (sign)
        *str++ = sign;
    if (type & SPECIAL) {
        if (base == 8)
            *str++ = '0';
        else if (base == 16) {
            *str++ = '0';
            *str++ = digits[33];
        }
    }
    if (!(type & LEFT))
        while (size-- > 0)
            *str++ = c;
    while (i < precision--)
        *str++ = '0';
    while (i-- > 0)
        *str++ = tmp[i];
    while (size-- > 0)
        *str++ = ' ';
    return str;
}

int ebpf_bvsnprintf(char *buf, int size, const char *fmt, uintptr_t *args) {
    int curr_args;
    int len, i;
    uint64_t num;
    uint base;
    int64_t t;
    int64_t t1, t2;
    char *str, *start;
    const char *s;

    int flags;        /* flags to number() */

    int field_width;    /* width of output field */
    int precision;        /* min. # of digits for integers; max
				   number of chars for from string */
    int qualifier;        /* 'h' or 'l' for integer fields */

    // nb_args = args[0];
    curr_args = 1; // 0 is the number of args

    for (start = str = buf; *fmt; ++fmt, size -= (str - start), start = str) {
        if (*fmt != '%') {
            if (!size)
                return -1;
            *str++ = *fmt;
            continue;
        }

        /* process flags */
        flags = 0;
        repeat:
        ++fmt;        /* this also skips first '%' */
        switch (*fmt) {
            case '-':
                flags |= LEFT;
                goto repeat;
            case '+':
                flags |= PLUS;
                goto repeat;
            case ' ':
                flags |= SPACE;
                goto repeat;
            case '#':
                flags |= SPECIAL;
                goto repeat;
            case '0':
                flags |= ZEROPAD;
                goto repeat;
        }

        /* get field width */
        field_width = -1;
        if (is_digit(*fmt))
            field_width = skip_atoi(&fmt);
        else if (*fmt == '*') {
            ++fmt;
            /* it's the next argument */
            field_width = (int) args[curr_args++];//va_arg(args, int);
            if (field_width < 0) {
                field_width = -field_width;
                flags |= LEFT;
            }
        }

        /* get the precision */
        precision = -1;
        if (*fmt == '.') {
            ++fmt;
            if (is_digit(*fmt))
                precision = skip_atoi(&fmt);
            else if (*fmt == '*') {
                ++fmt;
                /* it's the next argument */
                precision = (int) args[curr_args++];
            }
            if (precision < 0)
                precision = 0;
        }

        /* get the conversion qualifier */
        qualifier = -1;
        if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L') {
            qualifier = *fmt;
            ++fmt;
        }

        /* default base */
        base = 10;

        if (field_width > size)
            return -1;
        switch (*fmt) {
            case 'c':
                if (!(flags & LEFT))
                    while (--field_width > 0)
                        *str++ = ' ';
                *str++ = (uint8_t) args[curr_args++];
                while (--field_width > 0)
                    *str++ = ' ';
                continue;

            case 'm':
                if (flags & SPECIAL) {
                    if (!errno)
                        continue;
                    if (size < 2)
                        return -1;
                    *str++ = ':';
                    *str++ = ' ';
                    start += 2;
                    size -= 2;
                }
                s = strerror(errno);
                goto str;
            case 's':
                s = (char *) args[curr_args++];
                if (!s)
                    s = "<NULL>";

            str:
                len = strnlen(s, size); // prevent buffer overflow when wrong announced format
                if (precision >= 0 && len > precision)
                    len = precision;
                if (len > size)
                    return -1;

                if (!(flags & LEFT))
                    while (len < field_width--)
                        *str++ = ' ';
                for (i = 0; i < len; ++i)
                    *str++ = *s++;
                while (len < field_width--)
                    *str++ = ' ';
                continue;

                /*case 'V': { // put this case in standby ! (not really a good feature I guess)
                    const char *vfmt = (const char *) args[curr_args++];
                    va_list *vargs = va_arg(args, va_list *);
                    int res = bvsnprintf(str, size, vfmt, *vargs);
                    if (res < 0)
                        return -1;
                    str += res;
                    size -= res;
                    continue;
                }*/

            case 'p':
                if (field_width == -1) {
                    field_width = 2 * sizeof(void *);
                    flags |= ZEROPAD;
                }
                str = number(str, args[curr_args++], 16,
                             field_width, precision, flags, size);
                if (!str)
                    return -1;
                continue;

            case 'n':
                if (qualifier == 'l') {
                    int64_t *ip = (int64_t *) args[curr_args++];
                    *ip = (str - buf);
                } else {
                    int *ip = (int *) args[curr_args++];
                    *ip = (str - buf);
                }
                continue;


            case 't':
                t = (uint64_t) args[curr_args++];
                t1 = t TO_S;
                t2 = t - t1 S;

                if (precision < 0)
                    precision = 3;

                if (precision > 6)
                    precision = 6;

                /* Compute field_width for second part */
                if ((precision > 0) && (field_width > 0))
                    field_width -= (1 + precision);

                if (field_width < 0)
                    field_width = 0;

                /* Print seconds */
                flags |= SIGN;
                str = number(str, (uint64_t) t1, 10, field_width, 0, flags, size);
                if (!str)
                    return -1;

                if (precision > 0) {
                    size -= (str - start);
                    start = str;

                    if ((1 + precision) > size)
                        return -1;

                    /* Convert microseconds to requested precision */
                    for (i = precision; i < 6; i++)
                        t2 /= 10;

                    /* Print sub-seconds */
                    *str++ = '.';
                    str = number(str, (uint64_t) t2, 10, precision, 0, ZEROPAD, size - 1);
                    if (!str)
                        return -1;
                }
                goto done;

                /* integer number formats - set up the flags and "break" */
            case 'o':
                base = 8;
                break;

            case 'X':
                flags |= LARGE;
                /* fallthrough */
            case 'x':
                base = 16;
                break;

            case 'd':
            case 'i':
                flags |= SIGN;
            case 'u':
                break;

            default:
                if (size < 2)
                    return -1;
                if (*fmt != '%')
                    *str++ = '%';
                if (*fmt)
                    *str++ = *fmt;
                else
                    --fmt;
                continue;
        }
        if (flags & SIGN) {
            /* Conversions valid per ISO C99 6.3.1.3 (2) */
            if (qualifier == 'l')
                num = (uint64_t) args[curr_args++];
            else if (qualifier == 'h')
                num = (uint64_t) (
                        short) args[curr_args++];
            else
                num = (uint64_t) args[curr_args++];
        } else {
            if (qualifier == 'l')
                num = (uint64_t) args[curr_args++];
            else if (qualifier == 'h')
                num = (unsigned short) args[curr_args++];
            else
                num = (uint) args[curr_args++];
        }
        str = number(str, num, base, field_width, precision, flags, size);
        if (!str)
            return -1;
        done:;
    }
    if (!size)
        return -1;
    *str = '\0';
    return str - buf;
}

void *ctx_malloc(size_t size) {
    return malloc(size);
}

void *ctx_calloc(size_t nmemb, size_t size) {
    unsigned char *b = malloc(nmemb * size);
    memset(b, 0, nmemb * size);
    return b;
}

void *ctx_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

void ctx_free(void *ptr) {
    free(ptr);
}

static void *key_ptr[8192] = {0}; // 64 KiB

void *ctx_shmnew(key_t key, size_t size) {
    if (key_ptr[key]) return NULL;
    key_ptr[key] = malloc(size);
    return key_ptr[key];
}

void *ctx_shmget(key_t key) {
    return key_ptr[key];
}

void ctx_shmrm(key_t key) {
    if (key_ptr[key]) free(key_ptr[key]);
}

uint16_t ebpf_ntohs(uint16_t value) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return bswap_16(value);  // Compiler builtin GCC/Clang
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
#    error unsupported endianness
#endif
}

#ifndef PROVERS_T2
uint32_t ebpf_ntohl(uint32_t value) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return bswap_32(value);  // Compiler builtin GCC/Clang
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
#    error unsupported endianness
#endif
}
#else
uint32_t ebpf_ntohl(uint32_t value) {
    return 0;
}
#endif

uint64_t ebpf_ntohll(uint64_t value) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return bswap_64(value);  // Compiler builtin GCC/Clang
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
#    error unsupported endianness
#endif
}

uint16_t ebpf_htons(uint16_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return bswap_16(val);  // Compiler builtin GCC/Clang
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return val;
#else
#    error unsupported endianness
#endif
}

#ifndef PROVERS_T2
uint32_t ebpf_htonl(uint32_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return bswap_32(val);  // Compiler builtin GCC/Clang
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return val;
#else
#    error unsupported endianness
#endif
}
#else
unsigned int ebpf_htonl(unsigned int val) {
    return 0;
}
#endif

uint64_t ebpf_htonll(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return bswap_64(val);  // Compiler builtin GCC/Clang
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return val;
#else
#    error unsupported endianness
#endif
}

/*void *get_arg(unsigned int type) {
    return NULL; // to be changed according to the plugin
}*/

static unsigned int my_pow(unsigned x, unsigned y) {
    int i;
    unsigned res = 1;

    for (i = 0; i < y; i++) {
        res *= x;
    }

    return res;
}

uint64_t nondet_sqrt(uint64_t a);

uint64_t ebpf_sqrt(uint64_t a, unsigned int precision) {
    /* playing with double is a mess... */
    uint64_t ma = nondet_sqrt(a);
#ifdef PROVERS_CBMC
    __CPROVER_assume(ma < UINT32_MAX);
#endif

    return ma * my_pow(10, precision);
}

int get_extra_info_value(struct global_info *info__ UNUSED,
                         void *buf UNUSED, size_t len_buf UNUSED) {
    return 0;
}

int get_extra_info_lst_idx(struct global_info *info__ UNUSED,
                           int arr_idx UNUSED, struct global_info *value UNUSED) {
    return 0;
}

int get_extra_info_dict(struct global_info *info__ UNUSED,
                        const char *key UNUSED, struct global_info *value UNUSED) {
    return 0;
}

int get_extra_info(const char *key UNUSED, struct global_info *info__ UNUSED) {
    return 0;
}

int write_to_buffer(uint8_t *ptr, size_t len) {
    unsigned char *buf = malloc(len);
    if (!buf) return -1;
    memcpy(buf, ptr, len);
    free(buf);
    return 0;
}


#ifndef PROVERS_T2
// simple function that walk to the data
// doing stuff to trick the compiler to generate
// code
int set_attr(UNUSED struct path_attribute *attr) {
#define dec(j) ((j) == 0 ? (j) : (j)-1u)
#define odd(j) ((j) % 2 != 0 ? 1 : 0)
    unsigned char minibuf[5];
    unsigned int i;
    unsigned char dval;
    // i < 4096 limits the unrolling of loops
    // 4096 is the upper bound for BGP messages
    for (i = 0; i < attr->length && i < 4096; i++) {
        dval = attr->data[i];
        minibuf[i % 5u] = odd(dval) ? minibuf[dec(i) % 5] : dval;
    }
    return odd(minibuf[0]) ? -1 : 0;
}
#else
int set_attr(UNUSED struct path_attribute *attr) {
    return 0;
}
#endif

