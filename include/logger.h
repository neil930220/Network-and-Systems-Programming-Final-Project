/*
 * logger.h - Structured Audit Logging System
 * 
 * Provides logging with multiple levels, timestamps, and context tags.
 * Supports both console and file output.
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>

/* Log levels (use LEVEL_ prefix to avoid conflicts with macros) */
#define LEVEL_DEBUG  0   /* Detailed debugging (protocol dumps, state changes) */
#define LEVEL_INFO   1   /* Normal operations (connections, transactions) */
#define LEVEL_WARN   2   /* Recoverable issues (CRC failures, rate limits) */
#define LEVEL_ERROR  3   /* Serious errors (auth failures, crashes) */
#define LEVEL_AUDIT  4   /* Security events (always logged regardless of level) */

/* Log output destinations */
#define LOG_DEST_NONE    0x00
#define LOG_DEST_STDOUT  0x01
#define LOG_DEST_STDERR  0x02
#define LOG_DEST_FILE    0x04

/* Color control */
#define LOG_COLOR_AUTO   0
#define LOG_COLOR_ON     1
#define LOG_COLOR_OFF    2

/* Maximum log message length */
#define LOG_MAX_MSG      4096

/* Log context for tagging messages */
typedef struct {
    int worker_id;       /* Worker process ID (-1 for master) */
    int conn_id;         /* Connection FD or ID (-1 if N/A) */
    const char *module;  /* Module name (e.g., "proto", "auth") */
} log_ctx_t;

/*
 * Initialize logging system.
 * 
 * @param level     Minimum log level to output (LEVEL_DEBUG to LEVEL_AUDIT)
 * @param dest      Output destination(s) (LOG_DEST_* flags OR'd together)
 * @param log_file  Path to log file (NULL if not using file output)
 * @param color     Color mode (LOG_COLOR_AUTO, LOG_COLOR_ON, LOG_COLOR_OFF)
 * @return          0 on success, -1 on error
 */
int log_init(int level, int dest, const char *log_file, int color);

/*
 * Shutdown logging system and flush buffers.
 */
void log_shutdown(void);

/*
 * Set the minimum log level dynamically.
 */
void log_set_level(int level);

/*
 * Get the current log level.
 */
int log_get_level(void);

/*
 * Log a message with context.
 * 
 * @param level  Log level (LEVEL_DEBUG, LEVEL_INFO, etc.)
 * @param ctx    Log context (can be NULL for no context)
 * @param fmt    Printf-style format string
 * @param ...    Format arguments
 */
void log_msg(int level, const log_ctx_t *ctx, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/*
 * Log a message with context (va_list version).
 */
void log_vmsg(int level, const log_ctx_t *ctx, const char *fmt, va_list args);

/*
 * Convenience macros for logging with automatic file/line info.
 * Use these in application code.
 */

/* Create a context for the current worker/connection */
#define LOG_CTX(worker, conn) \
    (log_ctx_t){ .worker_id = (worker), .conn_id = (conn), .module = NULL }

#define LOG_CTX_MODULE(worker, conn, mod) \
    (log_ctx_t){ .worker_id = (worker), .conn_id = (conn), .module = (mod) }

/* Simple logging macros (no context) */
#define LOG_DEBUG(fmt, ...) log_msg(LEVEL_DEBUG, NULL, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_msg(LEVEL_INFO, NULL, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_msg(LEVEL_WARN, NULL, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_msg(LEVEL_ERROR, NULL, fmt, ##__VA_ARGS__)
#define LOG_AUDIT(fmt, ...) log_msg(LEVEL_AUDIT, NULL, fmt, ##__VA_ARGS__)

/* Logging macros with context */
#define LOG_DEBUG_CTX(ctx, fmt, ...) log_msg(LEVEL_DEBUG, &(ctx), fmt, ##__VA_ARGS__)
#define LOG_INFO_CTX(ctx, fmt, ...)  log_msg(LEVEL_INFO, &(ctx), fmt, ##__VA_ARGS__)
#define LOG_WARN_CTX(ctx, fmt, ...)  log_msg(LEVEL_WARN, &(ctx), fmt, ##__VA_ARGS__)
#define LOG_ERROR_CTX(ctx, fmt, ...) log_msg(LEVEL_ERROR, &(ctx), fmt, ##__VA_ARGS__)
#define LOG_AUDIT_CTX(ctx, fmt, ...) log_msg(LEVEL_AUDIT, &(ctx), fmt, ##__VA_ARGS__)

/*
 * Hex dump for debugging protocol data.
 * 
 * @param level   Log level
 * @param ctx     Log context (can be NULL)
 * @param prefix  Prefix string for the dump
 * @param data    Data to dump
 * @param len     Length of data
 */
void log_hexdump(int level, const log_ctx_t *ctx, const char *prefix, 
                 const uint8_t *data, size_t len);

/*
 * Log runtime statistics.
 * 
 * @param requests    Total requests processed
 * @param errors      Total errors
 * @param connections Active connections
 * @param uptime_sec  Server uptime in seconds
 */
void log_stats(uint64_t requests, uint64_t errors, uint32_t connections, 
               uint64_t uptime_sec);

/*
 * Flush log buffers immediately.
 */
void log_flush(void);

/*
 * Check if a log level is enabled.
 */
static inline int log_level_enabled(int level) {
    extern int g_log_level;
    return level >= g_log_level || level == LEVEL_AUDIT;
}

#endif /* LOGGER_H */
