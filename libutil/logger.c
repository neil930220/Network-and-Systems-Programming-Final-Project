/*
 * logger.c - Structured Audit Logging System Implementation
 * 
 * Provides thread-safe logging with timestamps, levels, and context.
 */

#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

/* ANSI color codes */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_MAGENTA "\033[0;35m"
#define COLOR_CYAN    "\033[0;36m"
#define COLOR_BOLD    "\033[1m"

/* Global log state */
int g_log_level = LEVEL_INFO;
static int g_log_dest = LOG_DEST_STDOUT;
static int g_log_color = LOG_COLOR_AUTO;
static int g_use_colors = 0;
static FILE *g_log_file = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Level names and colors */
static const char *level_names[] = {
    "DEBUG", "INFO ", "WARN ", "ERROR", "AUDIT"
};

static const char *level_colors[] = {
    COLOR_CYAN,    /* DEBUG - cyan */
    COLOR_GREEN,   /* INFO - green */
    COLOR_YELLOW,  /* WARN - yellow */
    COLOR_RED,     /* ERROR - red */
    COLOR_MAGENTA  /* AUDIT - magenta */
};

/*
 * Initialize logging system.
 */
int log_init(int level, int dest, const char *log_file, int color) {
    pthread_mutex_lock(&g_log_mutex);
    
    g_log_level = level;
    g_log_dest = dest;
    g_log_color = color;
    
    /* Determine if colors should be used */
    if (color == LOG_COLOR_ON) {
        g_use_colors = 1;
    } else if (color == LOG_COLOR_OFF) {
        g_use_colors = 0;
    } else {
        /* Auto-detect: use colors if stdout is a tty */
        g_use_colors = isatty(STDOUT_FILENO);
    }
    
    /* Open log file if requested */
    if ((dest & LOG_DEST_FILE) && log_file) {
        g_log_file = fopen(log_file, "a");
        if (!g_log_file) {
            pthread_mutex_unlock(&g_log_mutex);
            return -1;
        }
        /* Set line buffering for log file */
        setvbuf(g_log_file, NULL, _IOLBF, 0);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
    return 0;
}

/*
 * Shutdown logging system.
 */
void log_shutdown(void) {
    pthread_mutex_lock(&g_log_mutex);
    
    if (g_log_file) {
        fflush(g_log_file);
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}

/*
 * Set log level dynamically.
 */
void log_set_level(int level) {
    if (level >= LEVEL_DEBUG && level <= LEVEL_AUDIT) {
        g_log_level = level;
    }
}

/*
 * Get current log level.
 */
int log_get_level(void) {
    return g_log_level;
}

/*
 * Format timestamp with milliseconds.
 */
static void format_timestamp(char *buf, size_t size) {
    struct timeval tv;
    struct tm *tm;
    
    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);
    
    snprintf(buf, size, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec,
             (int)(tv.tv_usec / 1000));
}

/*
 * Format context tags.
 */
static void format_context(char *buf, size_t size, const log_ctx_t *ctx) {
    if (!ctx) {
        buf[0] = '\0';
        return;
    }
    
    char worker_str[32] = "";
    char conn_str[32] = "";
    char module_str[64] = "";
    
    if (ctx->worker_id >= 0) {
        snprintf(worker_str, sizeof(worker_str), "[worker:%d]", ctx->worker_id);
    }
    
    if (ctx->conn_id >= 0) {
        snprintf(conn_str, sizeof(conn_str), "[conn:%d]", ctx->conn_id);
    }
    
    if (ctx->module) {
        snprintf(module_str, sizeof(module_str), "[%s]", ctx->module);
    }
    
    snprintf(buf, size, "%s%s%s", worker_str, conn_str, module_str);
}

/*
 * Internal log output function.
 */
static void log_output(int level, const log_ctx_t *ctx, const char *msg) {
    char timestamp[64];
    char context[128];
    
    format_timestamp(timestamp, sizeof(timestamp));
    format_context(context, sizeof(context), ctx);
    
    pthread_mutex_lock(&g_log_mutex);
    
    /* Output to stdout/stderr */
    if (g_log_dest & (LOG_DEST_STDOUT | LOG_DEST_STDERR)) {
        FILE *out = (g_log_dest & LOG_DEST_STDERR) ? stderr : stdout;
        
        if (g_use_colors) {
            fprintf(out, "[%s] [%s%s%s] %s %s\n",
                    timestamp,
                    level_colors[level], level_names[level], COLOR_RESET,
                    context,
                    msg);
        } else {
            fprintf(out, "[%s] [%s] %s %s\n",
                    timestamp,
                    level_names[level],
                    context,
                    msg);
        }
        fflush(out);
    }
    
    /* Output to file (no colors) */
    if ((g_log_dest & LOG_DEST_FILE) && g_log_file) {
        fprintf(g_log_file, "[%s] [%s] %s %s\n",
                timestamp,
                level_names[level],
                context,
                msg);
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}

/*
 * Log a message with context.
 */
void log_msg(int level, const log_ctx_t *ctx, const char *fmt, ...) {
    /* Check if level is enabled (AUDIT always passes) */
    if (level < g_log_level && level != LEVEL_AUDIT) {
        return;
    }
    
    va_list args;
    va_start(args, fmt);
    log_vmsg(level, ctx, fmt, args);
    va_end(args);
}

/*
 * Log a message with context (va_list version).
 */
void log_vmsg(int level, const log_ctx_t *ctx, const char *fmt, va_list args) {
    /* Check if level is enabled (AUDIT always passes) */
    if (level < g_log_level && level != LEVEL_AUDIT) {
        return;
    }
    
    char msg[LOG_MAX_MSG];
    vsnprintf(msg, sizeof(msg), fmt, args);
    
    log_output(level, ctx, msg);
}

/*
 * Hex dump for debugging.
 */
void log_hexdump(int level, const log_ctx_t *ctx, const char *prefix,
                 const uint8_t *data, size_t len) {
    if (level < g_log_level && level != LEVEL_AUDIT) {
        return;
    }
    
    char line[256];
    char hex_part[128];
    char ascii_part[32];
    
    log_msg(level, ctx, "%s (%zu bytes):", prefix, len);
    
    for (size_t i = 0; i < len; i += 16) {
        size_t line_len = (len - i < 16) ? len - i : 16;
        
        /* Format hex part */
        char *hp = hex_part;
        for (size_t j = 0; j < 16; j++) {
            if (j < line_len) {
                hp += sprintf(hp, "%02X ", data[i + j]);
            } else {
                hp += sprintf(hp, "   ");
            }
            if (j == 7) *hp++ = ' ';
        }
        
        /* Format ASCII part */
        char *ap = ascii_part;
        for (size_t j = 0; j < line_len; j++) {
            uint8_t c = data[i + j];
            *ap++ = (c >= 32 && c < 127) ? c : '.';
        }
        *ap = '\0';
        
        snprintf(line, sizeof(line), "  %04zx: %s |%s|", i, hex_part, ascii_part);
        log_output(level, ctx, line);
    }
}

/*
 * Log runtime statistics.
 */
void log_stats(uint64_t requests, uint64_t errors, uint32_t connections,
               uint64_t uptime_sec) {
    double req_per_sec = (uptime_sec > 0) ? (double)requests / uptime_sec : 0;
    double error_rate = (requests > 0) ? (double)errors / requests * 100.0 : 0;
    
    uint64_t hours = uptime_sec / 3600;
    uint64_t mins = (uptime_sec % 3600) / 60;
    uint64_t secs = uptime_sec % 60;
    
    log_msg(LEVEL_INFO, NULL, "=== Server Statistics ===");
    log_msg(LEVEL_INFO, NULL, "  Uptime: %luh %lum %lus", 
            (unsigned long)hours, (unsigned long)mins, (unsigned long)secs);
    log_msg(LEVEL_INFO, NULL, "  Requests: %lu (%.1f/sec)",
            (unsigned long)requests, req_per_sec);
    log_msg(LEVEL_INFO, NULL, "  Errors: %lu (%.2f%%)",
            (unsigned long)errors, error_rate);
    log_msg(LEVEL_INFO, NULL, "  Active Connections: %u", connections);
}

/*
 * Flush log buffers.
 */
void log_flush(void) {
    pthread_mutex_lock(&g_log_mutex);
    
    fflush(stdout);
    fflush(stderr);
    if (g_log_file) {
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}
