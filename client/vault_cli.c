/*
 * vault_cli.c - ncurses-based Bank Vault TUI Client
 * 
 * A full-screen terminal user interface for banking operations.
 * Features: Visual menus, live connection status, transaction history table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <getopt.h>
#include <ncurses.h>
#include <signal.h>
#include <fcntl.h>

#include "protocol.h"
#include "common.h"

/* ============================================================
 * Configuration and Constants
 * ============================================================ */

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 7777
#define READ_TIMEOUT_SEC 5
#define MAX_HISTORY 100
#define MAX_INPUT_LEN 64

/* Window dimensions */
#define HEADER_HEIGHT 3
#define STATUS_HEIGHT 3
#define MENU_WIDTH 22
#define MIN_TERM_WIDTH 80
#define MIN_TERM_HEIGHT 24

/* Color pairs */
#define CP_HEADER     1
#define CP_MENU       2
#define CP_MENU_HL    3
#define CP_CONTENT    4
#define CP_STATUS     5
#define CP_OK         6
#define CP_ERROR      7
#define CP_WARN       8
#define CP_INPUT      9
#define CP_TABLE_HDR  10

/* Menu items */
typedef enum {
    MENU_LOGIN = 0,
    MENU_BALANCE,
    MENU_DEPOSIT,
    MENU_WITHDRAW,
    MENU_TRANSFER,
    MENU_HISTORY,
    MENU_RECONNECT,
    MENU_QUIT,
    MENU_COUNT
} menu_item_t;

static const char *menu_labels[] = {
    "Login",
    "Balance",
    "Deposit",
    "Withdraw",
    "Transfer",
    "History",
    "Reconnect",
    "Quit"
};

/* ============================================================
 * Data Structures
 * ============================================================ */

/* Session state */
typedef struct {
    int fd;
    int logged_in;
    int connected;
    uint32_t session_id;
    uint32_t session_key;
    char username[64];
    uint32_t seq;
} session_t;

/* Transaction history entry */
typedef struct {
    time_t timestamp;
    char operation[16];
    uint32_t account;
    int64_t amount;
    int64_t balance;
    int success;
    double latency_ms;
} history_entry_t;

/* Global state */
static session_t g_session = {0};
static char g_host[256] = DEFAULT_HOST;
static int g_port = DEFAULT_PORT;
static history_entry_t g_history[MAX_HISTORY];
static int g_history_count = 0;
static int g_history_scroll = 0;

/* Last operation status for status bar */
static char g_last_op[64] = "";
static double g_last_latency = 0.0;
static int g_last_status = -1;  /* -1 = none, 0 = ok, 1 = error */

/* Windows */
static WINDOW *win_header = NULL;
static WINDOW *win_menu = NULL;
static WINDOW *win_content = NULL;
static WINDOW *win_status = NULL;

/* Current menu selection */
static int g_menu_selection = 0;

/* Running flag */
static volatile int g_running = 1;

/* ============================================================
 * Utility Functions
 * ============================================================ */

/* Calculate time difference in milliseconds */
static double diff_ms(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000.0 +
           (b.tv_nsec - a.tv_nsec) / 1e6;
}

/* Get status code description */
static const char *status_str(uint16_t status) {
    switch (status) {
        case STATUS_OK: return "Success";
        case STATUS_ERR_BAD_MAGIC: return "Bad magic";
        case STATUS_ERR_BAD_VERSION: return "Bad version";
        case STATUS_ERR_BAD_LENGTH: return "Invalid length";
        case STATUS_ERR_TOO_LARGE: return "Too large";
        case STATUS_ERR_BAD_OPCODE: return "Unknown opcode";
        case STATUS_ERR_PARSE: return "Parse error";
        case STATUS_ERR_BAD_CRC: return "CRC failed";
        case STATUS_ERR_BAD_MAC: return "MAC failed";
        case STATUS_ERR_REPLAY: return "Replay detected";
        case STATUS_ERR_BAD_TIMESTAMP: return "Bad timestamp";
        case STATUS_ERR_NOT_AUTH: return "Not authenticated";
        case STATUS_ERR_AUTH_FAILED: return "Auth failed";
        case STATUS_ERR_AUTH_LOCKED: return "Account locked";
        case STATUS_ERR_SESSION_INVALID: return "Session invalid";
        case STATUS_ERR_PERMISSION: return "Permission denied";
        case STATUS_ERR_NO_ACCOUNT: return "Account not found";
        case STATUS_ERR_INSUFFICIENT: return "Insufficient funds";
        case STATUS_ERR_AMOUNT_INVALID: return "Invalid amount";
        case STATUS_ERR_TXN_CONFLICT: return "Txn conflict";
        case STATUS_ERR_RATE_LIMIT: return "Rate limited";
        case STATUS_ERR_TOO_MANY_CONN: return "Too many conn";
        case STATUS_ERR_SERVER_BUSY: return "Server busy";
        case STATUS_ERR_TIMEOUT: return "Timeout";
        case STATUS_ERR_INTERNAL: return "Internal error";
        case STATUS_ERR_IPC_FAIL: return "IPC failure";
        case STATUS_ERR_SHUTTING_DOWN: return "Shutting down";
        default: return "Unknown";
    }
}

/* ============================================================
 * Network Functions
 * ============================================================ */

/* Connect to server */
static int connect_to_server(void) {
    if (g_session.fd > 0) {
        close(g_session.fd);
        g_session.fd = 0;
    }
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    
    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = READ_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_port);
    
    if (inet_pton(AF_INET, g_host, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }
    
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    g_session.fd = fd;
    g_session.connected = 1;
    g_session.logged_in = 0;
    g_session.seq = 0;
    
    return 0;
}

/* Send request and receive response */
static int send_recv(frame_t *req, frame_t *resp, double *latency_ms) {
    struct timespec t1, t2;
    uint8_t *out;
    size_t out_len;
    
    req->seq = g_session.seq++;
    
    if (proto_encode(req, &out, &out_len) != 0) {
        return -1;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &t1);
    
    /* Send request */
    ssize_t sent = write(g_session.fd, out, out_len);
    free(out);
    
    if (sent != (ssize_t)out_len) {
        g_session.connected = 0;
        return -1;
    }
    
    /* Read response header */
    uint8_t buf[65536];
    ssize_t n = read(g_session.fd, buf, 4);
    if (n != 4) {
        g_session.connected = 0;
        return -1;
    }
    
    uint32_t pkt_len = ntohl(*(uint32_t *)buf);
    if (pkt_len > sizeof(buf) || pkt_len < HEADER_SIZE) {
        return -1;
    }
    
    /* Read rest of packet */
    size_t remaining = pkt_len - 4;
    size_t total_read = 4;
    while (remaining > 0) {
        n = read(g_session.fd, buf + total_read, remaining);
        if (n <= 0) {
            g_session.connected = 0;
            return -1;
        }
        total_read += n;
        remaining -= n;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &t2);
    if (latency_ms) *latency_ms = diff_ms(t1, t2);
    
    /* Decode response */
    return proto_decode(buf, pkt_len, resp);
}

/* Add entry to transaction history */
static void add_history(const char *op, uint32_t acct, int64_t amt, int64_t bal, int ok, double lat) {
    if (g_history_count >= MAX_HISTORY) {
        /* Shift history */
        memmove(&g_history[0], &g_history[1], sizeof(history_entry_t) * (MAX_HISTORY - 1));
        g_history_count = MAX_HISTORY - 1;
    }
    
    history_entry_t *e = &g_history[g_history_count++];
    e->timestamp = time(NULL);
    strncpy(e->operation, op, sizeof(e->operation) - 1);
    e->account = acct;
    e->amount = amt;
    e->balance = bal;
    e->success = ok;
    e->latency_ms = lat;
}

/* ============================================================
 * UI Drawing Functions
 * ============================================================ */

/* Initialize colors */
static void init_colors(void) {
    start_color();
    use_default_colors();
    
    init_pair(CP_HEADER, COLOR_WHITE, COLOR_BLUE);
    init_pair(CP_MENU, COLOR_WHITE, COLOR_BLACK);
    init_pair(CP_MENU_HL, COLOR_BLACK, COLOR_CYAN);
    init_pair(CP_CONTENT, COLOR_WHITE, -1);
    init_pair(CP_STATUS, COLOR_WHITE, COLOR_BLUE);
    init_pair(CP_OK, COLOR_GREEN, -1);
    init_pair(CP_ERROR, COLOR_RED, -1);
    init_pair(CP_WARN, COLOR_YELLOW, -1);
    init_pair(CP_INPUT, COLOR_CYAN, -1);
    init_pair(CP_TABLE_HDR, COLOR_YELLOW, -1);
}

/* Create windows */
static void create_windows(void) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    
    /* Clean up old windows */
    if (win_header) delwin(win_header);
    if (win_menu) delwin(win_menu);
    if (win_content) delwin(win_content);
    if (win_status) delwin(win_status);
    
    /* Calculate dimensions */
    int content_height = rows - HEADER_HEIGHT - STATUS_HEIGHT;
    int content_width = cols - MENU_WIDTH;
    
    /* Create windows */
    win_header = newwin(HEADER_HEIGHT, cols, 0, 0);
    win_menu = newwin(content_height, MENU_WIDTH, HEADER_HEIGHT, 0);
    win_content = newwin(content_height, content_width, HEADER_HEIGHT, MENU_WIDTH);
    win_status = newwin(STATUS_HEIGHT, cols, rows - STATUS_HEIGHT, 0);
    
    /* Enable keypad for all windows */
    keypad(win_menu, TRUE);
    keypad(win_content, TRUE);
}

/* Draw header */
static void draw_header(void) {
    int cols = getmaxx(win_header);
    
    wbkgd(win_header, COLOR_PAIR(CP_HEADER));
    werase(win_header);
    box(win_header, 0, 0);
    
    /* Title */
    wattron(win_header, A_BOLD);
    mvwprintw(win_header, 1, 2, "BANK VAULT TUI");
    wattroff(win_header, A_BOLD);
    
    /* Connection status */
    const char *status_text;
    int status_color;
    
    if (g_session.connected) {
        status_text = "[Connected]";
        status_color = CP_OK;
    } else {
        status_text = "[Disconnected]";
        status_color = CP_ERROR;
    }
    
    wattron(win_header, COLOR_PAIR(status_color) | A_BOLD);
    mvwprintw(win_header, 1, cols - 35, "%s", status_text);
    wattroff(win_header, COLOR_PAIR(status_color) | A_BOLD);
    
    /* Host info */
    mvwprintw(win_header, 1, cols - 20, "%s:%d", g_host, g_port);
    
    wrefresh(win_header);
}

/* Draw menu */
static void draw_menu(void) {
    werase(win_menu);
    box(win_menu, 0, 0);
    
    wattron(win_menu, A_BOLD);
    mvwprintw(win_menu, 1, 2, "MAIN MENU");
    wattroff(win_menu, A_BOLD);
    
    mvwhline(win_menu, 2, 1, ACS_HLINE, MENU_WIDTH - 2);
    
    for (int i = 0; i < MENU_COUNT; i++) {
        if (i == g_menu_selection) {
            wattron(win_menu, COLOR_PAIR(CP_MENU_HL) | A_BOLD);
        }
        
        mvwprintw(win_menu, 4 + i * 2, 2, "[%c] %s", 
                  (i == MENU_QUIT) ? 'Q' : '1' + i, 
                  menu_labels[i]);
        
        if (i == g_menu_selection) {
            wattroff(win_menu, COLOR_PAIR(CP_MENU_HL) | A_BOLD);
        }
    }
    
    /* Show logged in user */
    if (g_session.logged_in) {
        int rows = getmaxy(win_menu);
        wattron(win_menu, COLOR_PAIR(CP_OK));
        mvwprintw(win_menu, rows - 2, 2, "User: %s", g_session.username);
        wattroff(win_menu, COLOR_PAIR(CP_OK));
    }
    
    wrefresh(win_menu);
}

/* Draw status bar */
static void draw_status(void) {
    int cols = getmaxx(win_status);
    
    wbkgd(win_status, COLOR_PAIR(CP_STATUS));
    werase(win_status);
    box(win_status, 0, 0);
    
    /* Session info */
    if (g_session.logged_in) {
        mvwprintw(win_status, 1, 2, "Session: %s (0x%08X)", 
                  g_session.username, g_session.session_id);
    } else {
        mvwprintw(win_status, 1, 2, "Session: Not logged in");
    }
    
    /* Last operation */
    if (g_last_op[0] != '\0') {
        int color = (g_last_status == 0) ? CP_OK : CP_ERROR;
        wattron(win_status, COLOR_PAIR(color));
        mvwprintw(win_status, 1, cols / 3, "Last: %s", g_last_op);
        wattroff(win_status, COLOR_PAIR(color));
    }
    
    /* Latency */
    if (g_last_latency > 0) {
        mvwprintw(win_status, 1, cols - 20, "Latency: %.2fms", g_last_latency);
    }
    
    wrefresh(win_status);
}

/* Clear content area */
static void clear_content(void) {
    werase(win_content);
    box(win_content, 0, 0);
}

/* Show message in content area */
static void show_message(const char *title, const char *msg, int color_pair) {
    clear_content();
    
    wattron(win_content, A_BOLD);
    mvwprintw(win_content, 1, 2, "%s", title);
    wattroff(win_content, A_BOLD);
    
    mvwhline(win_content, 2, 1, ACS_HLINE, getmaxx(win_content) - 2);
    
    wattron(win_content, COLOR_PAIR(color_pair));
    mvwprintw(win_content, 4, 2, "%s", msg);
    wattroff(win_content, COLOR_PAIR(color_pair));
    
    wrefresh(win_content);
}

/* Get string input with echo */
static int get_input(const char *prompt, char *buf, int maxlen, int is_password) {
    (void)getmaxy(win_content);  /* Unused but call to satisfy ncurses */
    
    wattron(win_content, COLOR_PAIR(CP_INPUT));
    mvwprintw(win_content, 6, 2, "%s: ", prompt);
    wattroff(win_content, COLOR_PAIR(CP_INPUT));
    wrefresh(win_content);
    
    if (is_password) {
        noecho();
    } else {
        echo();
    }
    
    curs_set(1);
    
    int pos = 0;
    int ch;
    int start_x = strlen(prompt) + 4;
    
    wmove(win_content, 6, start_x);
    wclrtoeol(win_content);
    box(win_content, 0, 0);
    wrefresh(win_content);
    
    while ((ch = wgetch(win_content)) != '\n' && ch != KEY_ENTER) {
        if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (pos > 0) {
                pos--;
                buf[pos] = '\0';
                mvwaddch(win_content, 6, start_x + pos, ' ');
                wmove(win_content, 6, start_x + pos);
            }
        } else if (ch == 27) {  /* ESC */
            curs_set(0);
            noecho();
            return -1;
        } else if (isprint(ch) && pos < maxlen - 1) {
            buf[pos] = ch;
            buf[pos + 1] = '\0';
            if (is_password) {
                mvwaddch(win_content, 6, start_x + pos, '*');
            } else {
                mvwaddch(win_content, 6, start_x + pos, ch);
            }
            pos++;
        }
        wrefresh(win_content);
    }
    
    curs_set(0);
    noecho();
    buf[pos] = '\0';
    return pos;
}

/* Get numeric input */
static int get_number(const char *prompt, double *value) {
    char buf[32] = {0};
    if (get_input(prompt, buf, sizeof(buf), 0) <= 0) {
        return -1;
    }
    *value = atof(buf);
    return 0;
}

/* Get integer input */
static int get_integer(const char *prompt, uint32_t *value) {
    char buf[32] = {0};
    if (get_input(prompt, buf, sizeof(buf), 0) <= 0) {
        return -1;
    }
    *value = (uint32_t)atoi(buf);
    return 0;
}

/* ============================================================
 * Command Handlers
 * ============================================================ */

/* Login command */
static void cmd_login(void) {
    clear_content();
    wattron(win_content, A_BOLD);
    mvwprintw(win_content, 1, 2, "LOGIN");
    wattroff(win_content, A_BOLD);
    mvwhline(win_content, 2, 1, ACS_HLINE, getmaxx(win_content) - 2);
    
    mvwprintw(win_content, 4, 2, "Enter credentials (ESC to cancel):");
    wrefresh(win_content);
    
    char username[64] = {0};
    char password[64] = {0};
    
    if (get_input("Username", username, sizeof(username), 0) <= 0) {
        show_message("LOGIN", "Cancelled", CP_WARN);
        return;
    }
    
    wmove(win_content, 8, 2);
    wrefresh(win_content);
    
    if (get_input("Password", password, sizeof(password), 1) <= 0) {
        show_message("LOGIN", "Cancelled", CP_WARN);
        return;
    }
    
    /* Ensure connected */
    if (!g_session.connected) {
        if (connect_to_server() != 0) {
            snprintf(g_last_op, sizeof(g_last_op), "LOGIN FAILED (connect)");
            g_last_status = 1;
            show_message("LOGIN", "Failed to connect to server", CP_ERROR);
            return;
        }
        draw_header();
    }
    
    /* Build login body */
    uint8_t body[256];
    size_t off = 0;
    
    size_t user_len = strlen(username);
    size_t pass_len = strlen(password);
    
    body[off++] = (uint8_t)user_len;
    memcpy(body + off, username, user_len);
    off += user_len;
    body[off++] = (uint8_t)pass_len;
    memcpy(body + off, password, pass_len);
    off += pass_len;
    
    frame_t req = {
        .flags = 0,
        .opcode = OP_LOGIN,
        .body = body,
        .body_len = off
    };
    
    frame_t resp = {0};
    double latency;
    
    if (send_recv(&req, &resp, &latency) != 0) {
        snprintf(g_last_op, sizeof(g_last_op), "LOGIN FAILED (network)");
        g_last_status = 1;
        g_last_latency = 0;
        show_message("LOGIN", "Network error", CP_ERROR);
        draw_header();
        return;
    }
    
    g_last_latency = latency;
    
    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        if (status == STATUS_OK && resp.body_len >= 6) {
            g_session.session_id = ntohl(*(uint32_t *)(resp.body + 2));
            g_session.session_key = proto_derive_key(username, g_session.session_id);
            g_session.logged_in = 1;
            snprintf(g_session.username, sizeof(g_session.username), "%s", username);
            
            snprintf(g_last_op, sizeof(g_last_op), "LOGIN OK (%s)", username);
            g_last_status = 0;
            
            char msg[128];
            snprintf(msg, sizeof(msg), "Welcome, %s!\nSession ID: 0x%08X\nLatency: %.2f ms", 
                     username, g_session.session_id, latency);
            show_message("LOGIN", msg, CP_OK);
        } else {
            snprintf(g_last_op, sizeof(g_last_op), "LOGIN FAILED");
            g_last_status = 1;
            
            char msg[128];
            snprintf(msg, sizeof(msg), "Login failed: %s (0x%04X)", status_str(status), status);
            show_message("LOGIN", msg, CP_ERROR);
        }
    }
    
    if (resp.body) free(resp.body);
    draw_menu();
    draw_status();
}

/* Balance command */
static void cmd_balance(void) {
    if (!g_session.logged_in) {
        show_message("BALANCE", "Please login first", CP_WARN);
        return;
    }
    
    clear_content();
    wattron(win_content, A_BOLD);
    mvwprintw(win_content, 1, 2, "BALANCE QUERY");
    wattroff(win_content, A_BOLD);
    mvwhline(win_content, 2, 1, ACS_HLINE, getmaxx(win_content) - 2);
    
    mvwprintw(win_content, 4, 2, "Enter account ID (ESC to cancel):");
    wrefresh(win_content);
    
    uint32_t acct_id;
    if (get_integer("Account ID", &acct_id) < 0) {
        show_message("BALANCE", "Cancelled", CP_WARN);
        return;
    }
    
    uint32_t nacct = htonl(acct_id);
    
    frame_t req = {
        .flags = 0,
        .opcode = OP_BALANCE,
        .body = (uint8_t *)&nacct,
        .body_len = 4
    };
    
    frame_t resp = {0};
    double latency;
    
    if (send_recv(&req, &resp, &latency) != 0) {
        snprintf(g_last_op, sizeof(g_last_op), "BALANCE FAILED");
        g_last_status = 1;
        show_message("BALANCE", "Network error", CP_ERROR);
        draw_header();
        return;
    }
    
    g_last_latency = latency;
    
    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        if (status == STATUS_OK && resp.body_len >= 10) {
            int64_t balance = be64toh(*(int64_t *)(resp.body + 2));
            double dollars = balance / 100.0;
            
            snprintf(g_last_op, sizeof(g_last_op), "BALANCE #%u $%.2f", acct_id, dollars);
            g_last_status = 0;
            
            add_history("BALANCE", acct_id, 0, balance, 1, latency);
            
            char msg[128];
            snprintf(msg, sizeof(msg), "Account #%u\n\nBalance: $%.2f\n\nLatency: %.2f ms", 
                     acct_id, dollars, latency);
            show_message("BALANCE", msg, CP_OK);
        } else {
            snprintf(g_last_op, sizeof(g_last_op), "BALANCE FAILED");
            g_last_status = 1;
            add_history("BALANCE", acct_id, 0, 0, 0, latency);
            
            char msg[128];
            snprintf(msg, sizeof(msg), "Query failed: %s (0x%04X)", status_str(status), status);
            show_message("BALANCE", msg, CP_ERROR);
        }
    }
    
    if (resp.body) free(resp.body);
    draw_status();
}

/* Deposit command */
static void cmd_deposit(void) {
    if (!g_session.logged_in) {
        show_message("DEPOSIT", "Please login first", CP_WARN);
        return;
    }
    
    clear_content();
    wattron(win_content, A_BOLD);
    mvwprintw(win_content, 1, 2, "DEPOSIT");
    wattroff(win_content, A_BOLD);
    mvwhline(win_content, 2, 1, ACS_HLINE, getmaxx(win_content) - 2);
    
    mvwprintw(win_content, 4, 2, "Enter deposit details (ESC to cancel):");
    wrefresh(win_content);
    
    uint32_t acct_id;
    if (get_integer("Account ID", &acct_id) < 0) {
        show_message("DEPOSIT", "Cancelled", CP_WARN);
        return;
    }
    
    wmove(win_content, 8, 2);
    wrefresh(win_content);
    
    double amount_dollars;
    if (get_number("Amount ($)", &amount_dollars) < 0) {
        show_message("DEPOSIT", "Cancelled", CP_WARN);
        return;
    }
    
    if (amount_dollars <= 0) {
        show_message("DEPOSIT", "Amount must be positive", CP_ERROR);
        return;
    }
    
    int64_t amount_cents = (int64_t)(amount_dollars * 100 + 0.5);
    
    uint8_t body[12];
    uint32_t nacct = htonl(acct_id);
    int64_t namount = htobe64(amount_cents);
    memcpy(body, &nacct, 4);
    memcpy(body + 4, &namount, 8);
    
    frame_t req = {
        .flags = 0,
        .opcode = OP_DEPOSIT,
        .body = body,
        .body_len = 12
    };
    
    frame_t resp = {0};
    double latency;
    
    if (send_recv(&req, &resp, &latency) != 0) {
        snprintf(g_last_op, sizeof(g_last_op), "DEPOSIT FAILED");
        g_last_status = 1;
        show_message("DEPOSIT", "Network error", CP_ERROR);
        draw_header();
        return;
    }
    
    g_last_latency = latency;
    
    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        if (status == STATUS_OK && resp.body_len >= 10) {
            int64_t new_balance = be64toh(*(int64_t *)(resp.body + 2));
            
            snprintf(g_last_op, sizeof(g_last_op), "DEPOSIT $%.2f OK", amount_dollars);
            g_last_status = 0;
            
            add_history("DEPOSIT", acct_id, amount_cents, new_balance, 1, latency);
            
            char msg[128];
            snprintf(msg, sizeof(msg), "Deposited $%.2f to Account #%u\n\nNew Balance: $%.2f\n\nLatency: %.2f ms", 
                     amount_dollars, acct_id, new_balance / 100.0, latency);
            show_message("DEPOSIT", msg, CP_OK);
        } else {
            snprintf(g_last_op, sizeof(g_last_op), "DEPOSIT FAILED");
            g_last_status = 1;
            add_history("DEPOSIT", acct_id, amount_cents, 0, 0, latency);
            
            char msg[128];
            snprintf(msg, sizeof(msg), "Deposit failed: %s (0x%04X)", status_str(status), status);
            show_message("DEPOSIT", msg, CP_ERROR);
        }
    }
    
    if (resp.body) free(resp.body);
    draw_status();
}

/* Withdraw command */
static void cmd_withdraw(void) {
    if (!g_session.logged_in) {
        show_message("WITHDRAW", "Please login first", CP_WARN);
        return;
    }
    
    clear_content();
    wattron(win_content, A_BOLD);
    mvwprintw(win_content, 1, 2, "WITHDRAW");
    wattroff(win_content, A_BOLD);
    mvwhline(win_content, 2, 1, ACS_HLINE, getmaxx(win_content) - 2);
    
    mvwprintw(win_content, 4, 2, "Enter withdrawal details (ESC to cancel):");
    wrefresh(win_content);
    
    uint32_t acct_id;
    if (get_integer("Account ID", &acct_id) < 0) {
        show_message("WITHDRAW", "Cancelled", CP_WARN);
        return;
    }
    
    wmove(win_content, 8, 2);
    wrefresh(win_content);
    
    double amount_dollars;
    if (get_number("Amount ($)", &amount_dollars) < 0) {
        show_message("WITHDRAW", "Cancelled", CP_WARN);
        return;
    }
    
    if (amount_dollars <= 0) {
        show_message("WITHDRAW", "Amount must be positive", CP_ERROR);
        return;
    }
    
    int64_t amount_cents = (int64_t)(amount_dollars * 100 + 0.5);
    
    uint8_t body[12];
    uint32_t nacct = htonl(acct_id);
    int64_t namount = htobe64(amount_cents);
    memcpy(body, &nacct, 4);
    memcpy(body + 4, &namount, 8);
    
    frame_t req = {
        .flags = 0,
        .opcode = OP_WITHDRAW,
        .body = body,
        .body_len = 12
    };
    
    frame_t resp = {0};
    double latency;
    
    if (send_recv(&req, &resp, &latency) != 0) {
        snprintf(g_last_op, sizeof(g_last_op), "WITHDRAW FAILED");
        g_last_status = 1;
        show_message("WITHDRAW", "Network error", CP_ERROR);
        draw_header();
        return;
    }
    
    g_last_latency = latency;
    
    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        if (status == STATUS_OK && resp.body_len >= 10) {
            int64_t new_balance = be64toh(*(int64_t *)(resp.body + 2));
            
            snprintf(g_last_op, sizeof(g_last_op), "WITHDRAW $%.2f OK", amount_dollars);
            g_last_status = 0;
            
            add_history("WITHDRAW", acct_id, amount_cents, new_balance, 1, latency);
            
            char msg[128];
            snprintf(msg, sizeof(msg), "Withdrew $%.2f from Account #%u\n\nNew Balance: $%.2f\n\nLatency: %.2f ms", 
                     amount_dollars, acct_id, new_balance / 100.0, latency);
            show_message("WITHDRAW", msg, CP_OK);
        } else {
            snprintf(g_last_op, sizeof(g_last_op), "WITHDRAW FAILED");
            g_last_status = 1;
            add_history("WITHDRAW", acct_id, amount_cents, 0, 0, latency);
            
            char msg[128];
            snprintf(msg, sizeof(msg), "Withdrawal failed: %s (0x%04X)", status_str(status), status);
            show_message("WITHDRAW", msg, CP_ERROR);
        }
    }
    
    if (resp.body) free(resp.body);
    draw_status();
}

/* Transfer command */
static void cmd_transfer(void) {
    if (!g_session.logged_in) {
        show_message("TRANSFER", "Please login first", CP_WARN);
        return;
    }
    
    clear_content();
    wattron(win_content, A_BOLD);
    mvwprintw(win_content, 1, 2, "TRANSFER");
    wattroff(win_content, A_BOLD);
    mvwhline(win_content, 2, 1, ACS_HLINE, getmaxx(win_content) - 2);
    
    mvwprintw(win_content, 4, 2, "Enter transfer details (ESC to cancel):");
    wrefresh(win_content);
    
    uint32_t from_id, to_id;
    double amount_dollars;
    
    if (get_integer("From Account", &from_id) < 0) {
        show_message("TRANSFER", "Cancelled", CP_WARN);
        return;
    }
    
    wmove(win_content, 8, 2);
    wrefresh(win_content);
    
    if (get_integer("To Account", &to_id) < 0) {
        show_message("TRANSFER", "Cancelled", CP_WARN);
        return;
    }
    
    wmove(win_content, 10, 2);
    wrefresh(win_content);
    
    if (get_number("Amount ($)", &amount_dollars) < 0) {
        show_message("TRANSFER", "Cancelled", CP_WARN);
        return;
    }
    
    if (amount_dollars <= 0) {
        show_message("TRANSFER", "Amount must be positive", CP_ERROR);
        return;
    }
    
    if (from_id == to_id) {
        show_message("TRANSFER", "Source and destination must be different", CP_ERROR);
        return;
    }
    
    int64_t amount_cents = (int64_t)(amount_dollars * 100 + 0.5);
    
    uint8_t body[16];
    uint32_t nfrom = htonl(from_id);
    uint32_t nto = htonl(to_id);
    int64_t namount = htobe64(amount_cents);
    memcpy(body, &nfrom, 4);
    memcpy(body + 4, &nto, 4);
    memcpy(body + 8, &namount, 8);
    
    frame_t req = {
        .flags = 0,
        .opcode = OP_TRANSFER,
        .body = body,
        .body_len = 16
    };
    
    frame_t resp = {0};
    double latency;
    
    if (send_recv(&req, &resp, &latency) != 0) {
        snprintf(g_last_op, sizeof(g_last_op), "TRANSFER FAILED");
        g_last_status = 1;
        show_message("TRANSFER", "Network error", CP_ERROR);
        draw_header();
        return;
    }
    
    g_last_latency = latency;
    
    if (resp.body_len >= 2) {
        uint16_t status = ntohs(*(uint16_t *)resp.body);
        if (status == STATUS_OK && resp.body_len >= 18) {
            int64_t from_balance = be64toh(*(int64_t *)(resp.body + 2));
            int64_t to_balance = be64toh(*(int64_t *)(resp.body + 10));
            
            snprintf(g_last_op, sizeof(g_last_op), "TRANSFER $%.2f OK", amount_dollars);
            g_last_status = 0;
            
            add_history("TRANSFER", from_id, amount_cents, from_balance, 1, latency);
            
            char msg[256];
            snprintf(msg, sizeof(msg), 
                     "Transferred $%.2f from #%u to #%u\n\n"
                     "Account #%u Balance: $%.2f\n"
                     "Account #%u Balance: $%.2f\n\n"
                     "Latency: %.2f ms", 
                     amount_dollars, from_id, to_id,
                     from_id, from_balance / 100.0,
                     to_id, to_balance / 100.0,
                     latency);
            show_message("TRANSFER", msg, CP_OK);
        } else {
            snprintf(g_last_op, sizeof(g_last_op), "TRANSFER FAILED");
            g_last_status = 1;
            add_history("TRANSFER", from_id, amount_cents, 0, 0, latency);
            
            char msg[128];
            snprintf(msg, sizeof(msg), "Transfer failed: %s (0x%04X)", status_str(status), status);
            show_message("TRANSFER", msg, CP_ERROR);
        }
    }
    
    if (resp.body) free(resp.body);
    draw_status();
}

/* History command - show transaction table */
static void cmd_history(void) {
    if (g_history_count == 0) {
        show_message("TRANSACTION HISTORY", "No transactions recorded", CP_WARN);
        return;
    }
    
    int rows, cols;
    getmaxyx(win_content, rows, cols);
    
    int visible_rows = rows - 6;  /* Header + borders */
    int max_scroll = (g_history_count > visible_rows) ? g_history_count - visible_rows : 0;
    
    g_history_scroll = 0;
    
    while (1) {
        clear_content();
        wattron(win_content, A_BOLD);
        mvwprintw(win_content, 1, 2, "TRANSACTION HISTORY (%d entries)", g_history_count);
        wattroff(win_content, A_BOLD);
        mvwhline(win_content, 2, 1, ACS_HLINE, cols - 2);
        
        /* Table header */
        wattron(win_content, COLOR_PAIR(CP_TABLE_HDR) | A_BOLD);
        mvwprintw(win_content, 3, 2, "%-19s %-10s %-8s %-11s %-11s %-6s %-8s", 
                  "TIME", "OPERATION", "ACCOUNT", "AMOUNT", "BALANCE", "STATUS", "LATENCY");
        wattroff(win_content, COLOR_PAIR(CP_TABLE_HDR) | A_BOLD);
        
        /* Table rows */
        for (int i = 0; i < visible_rows && (g_history_scroll + i) < g_history_count; i++) {
            history_entry_t *e = &g_history[g_history_scroll + i];
            
            char time_buf[20];
            struct tm *tm = localtime(&e->timestamp);
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm);
            
            char amt_buf[12] = "-";
            char bal_buf[12] = "-";
            
            if (e->amount != 0) {
                snprintf(amt_buf, sizeof(amt_buf), "$%.2f", e->amount / 100.0);
            }
            if (e->balance != 0 || e->success) {
                snprintf(bal_buf, sizeof(bal_buf), "$%.2f", e->balance / 100.0);
            }
            
            int color = e->success ? CP_OK : CP_ERROR;
            const char *status = e->success ? "OK" : "FAIL";
            
            mvwprintw(win_content, 4 + i, 2, "%-19s %-10s %-8u %-11s %-11s ",
                      time_buf, e->operation, e->account, amt_buf, bal_buf);
            
            wattron(win_content, COLOR_PAIR(color));
            wprintw(win_content, "%-6s", status);
            wattroff(win_content, COLOR_PAIR(color));
            
            wprintw(win_content, " %.1fms", e->latency_ms);
        }
        
        /* Scroll indicator */
        if (max_scroll > 0) {
            wattron(win_content, COLOR_PAIR(CP_INPUT));
            mvwprintw(win_content, rows - 2, 2, "UP/DOWN to scroll, ESC/Q to close");
            wattroff(win_content, COLOR_PAIR(CP_INPUT));
        } else {
            wattron(win_content, COLOR_PAIR(CP_INPUT));
            mvwprintw(win_content, rows - 2, 2, "ESC or Q to close");
            wattroff(win_content, COLOR_PAIR(CP_INPUT));
        }
        
        wrefresh(win_content);
        
        int ch = wgetch(win_content);
        if (ch == 'q' || ch == 'Q' || ch == 27) {  /* ESC */
            break;
        } else if (ch == KEY_UP && g_history_scroll > 0) {
            g_history_scroll--;
        } else if (ch == KEY_DOWN && g_history_scroll < max_scroll) {
            g_history_scroll++;
        } else if (ch == KEY_PPAGE) {  /* Page Up */
            g_history_scroll -= visible_rows;
            if (g_history_scroll < 0) g_history_scroll = 0;
        } else if (ch == KEY_NPAGE) {  /* Page Down */
            g_history_scroll += visible_rows;
            if (g_history_scroll > max_scroll) g_history_scroll = max_scroll;
        }
    }
    
    show_message("TRANSACTION HISTORY", "Press any key to continue...", CP_CONTENT);
}

/* Reconnect command */
static void cmd_reconnect(void) {
    show_message("RECONNECT", "Connecting to server...", CP_INPUT);
    wrefresh(win_content);
    
    if (connect_to_server() == 0) {
        snprintf(g_last_op, sizeof(g_last_op), "RECONNECT OK");
        g_last_status = 0;
        g_session.logged_in = 0;  /* Need to re-login */
        show_message("RECONNECT", "Connected successfully!\n\nPlease login again.", CP_OK);
    } else {
        snprintf(g_last_op, sizeof(g_last_op), "RECONNECT FAILED");
        g_last_status = 1;
        show_message("RECONNECT", "Connection failed!", CP_ERROR);
    }
    
    draw_header();
    draw_menu();
    draw_status();
}

/* Show welcome screen */
static void show_welcome(void) {
    clear_content();
    int rows, cols;
    getmaxyx(win_content, rows, cols);
    
    wattron(win_content, A_BOLD);
    mvwprintw(win_content, 1, 2, "WELCOME TO BANK VAULT");
    wattroff(win_content, A_BOLD);
    mvwhline(win_content, 2, 1, ACS_HLINE, cols - 2);
    
    mvwprintw(win_content, 4, 2, "Use UP/DOWN arrows or number keys to navigate the menu.");
    mvwprintw(win_content, 5, 2, "Press ENTER to select an option.");
    mvwprintw(win_content, 7, 2, "Available Operations:");
    
    wattron(win_content, COLOR_PAIR(CP_INPUT));
    mvwprintw(win_content, 9, 4, "1. Login     - Authenticate with username and password");
    mvwprintw(win_content, 10, 4, "2. Balance   - Check account balance");
    mvwprintw(win_content, 11, 4, "3. Deposit   - Add funds to an account");
    mvwprintw(win_content, 12, 4, "4. Withdraw  - Remove funds from an account");
    mvwprintw(win_content, 13, 4, "5. Transfer  - Move funds between accounts");
    mvwprintw(win_content, 14, 4, "6. History   - View transaction history");
    mvwprintw(win_content, 15, 4, "7. Reconnect - Re-establish server connection");
    mvwprintw(win_content, 16, 4, "Q. Quit      - Exit the application");
    wattroff(win_content, COLOR_PAIR(CP_INPUT));
    
    if (!g_session.connected) {
        wattron(win_content, COLOR_PAIR(CP_WARN));
        mvwprintw(win_content, rows - 4, 2, "Warning: Not connected to server. Use Reconnect to connect.");
        wattroff(win_content, COLOR_PAIR(CP_WARN));
    }
    
    wrefresh(win_content);
}

/* ============================================================
 * Main Event Loop
 * ============================================================ */

/* Handle menu selection */
static void handle_menu_action(void) {
    switch (g_menu_selection) {
        case MENU_LOGIN:
            cmd_login();
            break;
        case MENU_BALANCE:
            cmd_balance();
            break;
        case MENU_DEPOSIT:
            cmd_deposit();
            break;
        case MENU_WITHDRAW:
            cmd_withdraw();
            break;
        case MENU_TRANSFER:
            cmd_transfer();
            break;
        case MENU_HISTORY:
            cmd_history();
            break;
        case MENU_RECONNECT:
            cmd_reconnect();
            break;
        case MENU_QUIT:
            g_running = 0;
            break;
    }
}

/* Signal handler for clean exit */
static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* Terminal resize handler */
static void handle_resize(void) {
    endwin();
    refresh();
    clear();
    
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    
    if (rows < MIN_TERM_HEIGHT || cols < MIN_TERM_WIDTH) {
        endwin();
        fprintf(stderr, "Terminal too small. Minimum: %dx%d\n", MIN_TERM_WIDTH, MIN_TERM_HEIGHT);
        exit(1);
    }
    
    create_windows();
    draw_header();
    draw_menu();
    draw_status();
    show_welcome();
}

/* Main function */
int main(int argc, char *argv[]) {
    /* Parse command line arguments */
    static struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"help", no_argument, 0, '?'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "h:p:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                strncpy(g_host, optarg, sizeof(g_host) - 1);
                break;
            case 'p':
                g_port = atoi(optarg);
                break;
            case '?':
            default:
                fprintf(stderr, "Usage: %s [--host HOST] [--port PORT]\n", argv[0]);
                return 1;
        }
    }
    
    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGWINCH, (void (*)(int))handle_resize);
    
    /* Initialize ncurses */
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    
    /* Check terminal size */
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    if (rows < MIN_TERM_HEIGHT || cols < MIN_TERM_WIDTH) {
        endwin();
        fprintf(stderr, "Terminal too small. Minimum: %dx%d, current: %dx%d\n", 
                MIN_TERM_WIDTH, MIN_TERM_HEIGHT, cols, rows);
        return 1;
    }
    
    /* Initialize colors */
    if (has_colors()) {
        init_colors();
    }
    
    /* Create windows */
    create_windows();
    
    /* Try initial connection */
    if (connect_to_server() == 0) {
        snprintf(g_last_op, sizeof(g_last_op), "Connected");
        g_last_status = 0;
    } else {
        snprintf(g_last_op, sizeof(g_last_op), "Not connected");
        g_last_status = 1;
    }
    
    /* Initial draw */
    draw_header();
    draw_menu();
    draw_status();
    show_welcome();
    
    /* Main event loop */
    while (g_running) {
        int ch = wgetch(win_menu);
        
        switch (ch) {
            case KEY_UP:
            case 'k':
                if (g_menu_selection > 0) {
                    g_menu_selection--;
                    draw_menu();
                }
                break;
                
            case KEY_DOWN:
            case 'j':
                if (g_menu_selection < MENU_COUNT - 1) {
                    g_menu_selection++;
                    draw_menu();
                }
                break;
                
            case KEY_ENTER:
            case '\n':
            case '\r':
                handle_menu_action();
                break;
                
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
                g_menu_selection = ch - '1';
                draw_menu();
                handle_menu_action();
                break;
                
            case 'q':
            case 'Q':
                g_running = 0;
                break;
                
            case KEY_RESIZE:
                handle_resize();
                break;
        }
    }
    
    /* Cleanup */
    if (g_session.fd > 0) {
        close(g_session.fd);
    }
    
    delwin(win_header);
    delwin(win_menu);
    delwin(win_content);
    delwin(win_status);
    endwin();
    
    printf("Goodbye!\n");
    return 0;
}
