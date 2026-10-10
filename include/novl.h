#ifndef NOVL_H
#define NOVL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the NOVL library version string (e.g. "0.1.0").
 */
const char* novl_version(void);

/**
 * Returns the last error message on the calling thread, or NULL.
 * The returned string must be released with novl_free_string().
 */
char* novl_last_error(void);

/**
 * Frees a string allocated by NOVL C-ABI functions.
 */
void novl_free_string(char* s);

/**
 * Opaque handle representing an active NOVL SOCKS5 client instance.
 */
typedef struct NovlClientHandle NovlClientHandle;

/**
 * Starts a background NOVL SOCKS5 client instance from a JSON configuration string.
 *
 * Example config JSON:
 * {
 *   "socks5_bind": "127.0.0.1:10800",
 *   "server_addr": "127.0.0.1:7443",
 *   "secret": "your-pre-shared-key",
 *   "sni": "addons.mozilla.org",
 *   "mode": "tls",
 *   "path": "/novl",
 *   "split_pos": 5,
 *   "split_delay_ms": 1
 * }
 *
 * @param config_json Null-terminated UTF-8 JSON configuration string.
 * @return Pointer to NovlClientHandle on success, or NULL on error (call novl_last_error()).
 */
NovlClientHandle* novl_start_client(const char* config_json);

/**
 * Stops a running NOVL client instance and releases all associated resources.
 *
 * @param handle Handle returned by novl_start_client().
 * @return 0 on success, -1 on error.
 */
int novl_stop_client(NovlClientHandle* handle);

#ifdef __cplusplus
}
#endif

#endif /* NOVL_H */
