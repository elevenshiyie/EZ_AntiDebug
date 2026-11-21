#include "whitelist.h"
#include "syscall_utils.h"
#include <pthread.h>

/* 单类白名单条目表。路径条目存子串；前缀条目存前缀；信号条目存信号号。 */
typedef struct {
    char paths[SG_WL_MAX][64];   /* 路径子串白名单 */
    int  path_n;
    char prefixes[SG_WL_MAX][64];/* 路径前缀白名单 */
    int  prefix_n;
    int  signals[SG_WL_MAX];     /* 信号号白名单 */
    int  signal_n;
    int  seccomp;                /* seccomp 白名单开关（0/1） */
} SgWhitelist;

static SgWhitelist g_wl;
static pthread_mutex_t g_wl_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- 注册 ---- */

int sg_wl_add_path(const char *substr) {
    if (!substr || !*substr) return -1;
    pthread_mutex_lock(&g_wl_lock);
    int rc = -1;
    if (g_wl.path_n < SG_WL_MAX) {
        sg_strncpy(g_wl.paths[g_wl.path_n], substr, sizeof(g_wl.paths[0]));
        g_wl.path_n++;
        rc = 0;
    }
    pthread_mutex_unlock(&g_wl_lock);
    return rc;
}

int sg_wl_add_path_prefix(const char *prefix) {
    if (!prefix || !*prefix) return -1;
    pthread_mutex_lock(&g_wl_lock);
    int rc = -1;
    if (g_wl.prefix_n < SG_WL_MAX) {
        sg_strncpy(g_wl.prefixes[g_wl.prefix_n], prefix, sizeof(g_wl.prefixes[0]));
        g_wl.prefix_n++;
        rc = 0;
    }
    pthread_mutex_unlock(&g_wl_lock);
    return rc;
}

int sg_wl_add_signal(int signo) {
    if (signo <= 0 || signo > 63) return -1;
    pthread_mutex_lock(&g_wl_lock);
    int rc = -1;
    if (g_wl.signal_n < SG_WL_MAX) {
        g_wl.signals[g_wl.signal_n] = signo;
        g_wl.signal_n++;
        rc = 0;
    }
    pthread_mutex_unlock(&g_wl_lock);
    return rc;
}

void sg_wl_set_seccomp(int enabled) {
    pthread_mutex_lock(&g_wl_lock);
    g_wl.seccomp = enabled ? 1 : 0;
    pthread_mutex_unlock(&g_wl_lock);
}

/* ---- 查询 ---- */

int sg_wl_match_path(const char *path) {
    if (!path || !*path) return 0;
    pthread_mutex_lock(&g_wl_lock);
    int hit = 0;
    for (int i = 0; i < g_wl.path_n; i++) {
        if (sg_strstr(path, g_wl.paths[i])) { hit = 1; break; }
    }
    pthread_mutex_unlock(&g_wl_lock);
    return hit;
}

int sg_wl_match_path_prefix(const char *path) {
    if (!path || !*path) return 0;
    pthread_mutex_lock(&g_wl_lock);
    int hit = 0;
    for (int i = 0; i < g_wl.prefix_n; i++) {
        if (sg_strncmp(path, g_wl.prefixes[i], sg_strlen(g_wl.prefixes[i])) == 0) {
            hit = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_wl_lock);
    return hit;
}

int sg_wl_match_signal(int signo) {
    pthread_mutex_lock(&g_wl_lock);
    int hit = 0;
    for (int i = 0; i < g_wl.signal_n; i++) {
        if (g_wl.signals[i] == signo) { hit = 1; break; }
    }
    pthread_mutex_unlock(&g_wl_lock);
    return hit;
}

int sg_wl_seccomp_enabled(void) {
    pthread_mutex_lock(&g_wl_lock);
    int v = g_wl.seccomp;
    pthread_mutex_unlock(&g_wl_lock);
    return v;
}
