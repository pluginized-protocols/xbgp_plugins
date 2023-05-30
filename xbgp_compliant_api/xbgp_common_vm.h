//
// Created by thomas on 6/12/21.
//

#ifndef XBGP_PLUGINS_XBGP_COMMON_VM_H
#define XBGP_PLUGINS_XBGP_COMMON_VM_H

#include <time.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "xbgp_common_vm_defs.h"

#if (!defined(__always_inline)) && defined(__GNUC__)
#define __always_inline __attribute__((always_inline))
#endif



#define ubpf_sprintf(str, size, format, ...)\
ebpf_bvsnprintf(str, size, format, (uintptr_t[]){NUMARGS_SPRINTF__(__VA_ARGS__), __VA_ARGS__})


#define var_fun(fun_name, format, ...) ({             \
      struct vargs __vargs__ = {                      \
          .nb_args = NUMARGS_LOGMSG(__VA_ARGS__),     \
          .args = (struct vtype[]) {                  \
              __VA_ARGS__                             \
          }                                           \
      };                                              \
      fun_name(format, &__vargs__);                  \
})

#define log_msg(format, ...) var_fun(super_log, format,##__VA_ARGS__)

#define ebpf_print(format, ...) var_fun(ebpf_print_intern, format,##__VA_ARGS__)


/**
 * Send data pointed by the first argument to the monitoring thread.
 * @param data pointer related to the data the uBPF wants to send to the monitor thread
 * @param len total length of the data
 * @param type which kind of monitoring data the uBPF plugin sends
 * @return 1 if the operation succeed
 *         0 otherwise ( - unable to reach the monitor
 *                       - out of memory when creating packet
 *                       - send failed )
 */
extern int send_to_monitor(const void *data, size_t len, unsigned int type);

extern int get_time(struct timespec *spec);

extern int get_realtime(struct timespec *spec);

extern clock_t bpf_clock(void);

extern void *ebpf_memcpy(void *dst0, const void *src0, size_t length);

extern int ebpf_print_intern(const char *format, struct vargs *args);

extern void set_error(const char *reason, size_t len);

extern void *ctx_malloc(size_t size);

extern void *ctx_calloc(size_t nmemb, size_t size);

extern void *ctx_realloc(void *ptr, size_t size);

extern void ctx_free(void *ptr);

extern void *ctx_shmnew(key_t key, size_t size);

extern void *ctx_shmget(key_t key);

extern void ctx_shmrm(key_t key);

extern uint16_t ebpf_ntohs(uint16_t value);

extern uint32_t ebpf_ntohl(uint32_t value);

extern uint64_t ebpf_ntohll(uint64_t value);

extern uint16_t ebpf_htons(uint16_t value);

extern uint32_t ebpf_htonl(uint32_t value);

extern uint64_t ebpf_htonll(uint64_t value);

extern void *get_arg(unsigned int arg_type);

extern int bpf_sockunion_cmp(const struct sockaddr *su1, const struct sockaddr *su2);

extern uint64_t ebpf_sqrt(uint64_t a, unsigned int precision);

extern int ebpf_memcmp(const void *s1, const void *s2, size_t n);

extern int ebpf_bvsnprintf(char *buf, int size, const char *fmt, uintptr_t *args);

extern int next(void);

extern int get_extra_info_value(struct global_info *info, void *buf, size_t len_buf);

extern int get_extra_info_lst_idx(struct global_info *info, int arr_idx, struct global_info *value);

extern int get_extra_info(const char *key, struct global_info *info);

extern int get_extra_info_dict(struct global_info *info, const char *key, struct global_info *value);

extern int ebpf_inet_ntop(uint8_t *ipaddr, int type, char *buf, size_t len);

int ebpf_inet_pton(int af, const char *src, void *dst, size_t buf_len);

extern int super_log(const char *msg, struct vargs *args);

extern int sock_open(sk_type_t proto, int af, const struct sockaddr *addr, socklen_t len);

extern int sock_write(int sfd, const void *buf, size_t len);

extern int sock_read(int sfd, void *buf, size_t len);

extern int sock_close(int sfd);

extern int reschedule_plugin(time_t *time);

extern int whereami(void);

#endif //XBGP_PLUGINS_XBGP_COMMON_VM_H
