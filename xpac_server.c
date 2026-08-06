#include "xpac_server.h"
#include "xlog.h"
#include <ctype.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define PATH_SEPARATOR '\\'
#define mkdir(dir) _mkdir(dir)
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#else
#include <unistd.h>
#include <sys/stat.h>
#define PATH_SEPARATOR '/'
#define mkdir(dir) mkdir(dir, 0755)
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <arpa/inet.h>
#endif

// ===================== 域名规则结构 =====================
typedef struct DomainRule {
    char pattern[256];            // 裸域名（如 "google.com"，匹配形态由PAC生成时派生）
    ProxyType proxy_type;         // 代理类型
    struct DomainRule* next;      // 链表下一个节点
} DomainRule;

typedef struct AllowIpRule {
    char ip[64];
    struct AllowIpRule* next;
} AllowIpRule;

/* 大流量分流域名（@bulk）：命中的目标域名走独立的 SSH 会话，
** 避免视频/下载流量把主会话的 TCP 连接灌满、阻塞新通道建立。 */
typedef struct BulkDomainRule {
    char domain[256];             // 裸域名，后缀匹配（如 "googlevideo.com"）
    struct BulkDomainRule* next;
} BulkDomainRule;

// ===================== 全局变量 =====================
static XpacConfig g_config = {
    .http_proxy_port = 7890,
    .socks5_proxy_port = 1080,
    .proxy_host = NULL,
    .config_file = NULL,
    .enable_web_admin = 1,        // 默认启用Web管理
    .enable_proxy_whitelist = 0,   // 默认不启用代理白名单
    .admin_username = "admin",
    .admin_password = NULL        // 默认无需密码
};

static DomainRule* g_domain_list = NULL;  // 域名规则链表头
static int g_domain_count = 0;            // 域名规则数量
static AllowIpRule* g_allow_ip_list = NULL;
static int g_allow_ip_count = 0;
static BulkDomainRule* g_bulk_domain_list = NULL;
static int g_bulk_domain_count = 0;
static int g_initialized = 0;             // 是否已初始化

// ===================== 内部工具函数声明 =====================
static int is_valid_domain_pattern(const char* pattern);
static DomainRule* find_domain_rule(const char* pattern);
static AllowIpRule* find_allow_ip_rule(const char* ip);
static void free_domain_list(void);
static void free_allow_ip_list(void);
static int parse_proxy_type(const char* type_str);
static const char* proxy_type_to_str(ProxyType type);
static int xpac_load_config(const char* filename);
static int parse_config_line(char* line, int line_num);
static int xpac_load_builtin_config(void);
static int xpac_save_config(const char* filename);
static const char* get_pac_proxy_address(void);

// ===================== 域名管理API =====================
static int xpac_add_domain(const char* pattern, ProxyType proxy_type);
static int xpac_remove_domain(const char* pattern);
static void xpac_clear_domains(void);
static int xpac_add_allow_ip(const char* ip);
static int xpac_remove_allow_ip(const char* ip);
static int xpac_add_bulk_domain(const char* domain);
static void free_bulk_domain_list(void);

// ===================== 初始化函数 =====================
void xpac_init(const XpacConfig* config) {
    if (g_initialized) {
        printf("[PAC] 警告：PAC服务器已初始化\n");
        return;
    }

    if (config) {
        g_config.http_proxy_port = config->http_proxy_port;
        g_config.socks5_proxy_port = config->socks5_proxy_port;
        g_config.enable_web_admin = config->enable_web_admin;
        g_config.bind_address = config->bind_address;
        g_config.proxy_host = config->proxy_host;
        g_config.config_file = config->config_file;
        g_config.admin_password = config->admin_password;
        g_config.admin_username = config->admin_username;
        g_config.enable_proxy_whitelist = config->enable_proxy_whitelist;
    }

    printf("[PAC] PAC服务器初始化完成\n");
    printf("[PAC] HTTP代理端口: %d, SOCKS5代理端口: %d\n",
           g_config.http_proxy_port, g_config.socks5_proxy_port);
    printf("[PAC] Web管理界面: %s\n",
           g_config.enable_web_admin ? "启用" : "禁用");
    printf("[PAC] 代理白名单: %s\n",
           g_config.enable_proxy_whitelist ? "启用" : "禁用");

    // 尝试加载配置文件；失败时回退到 exe 内置的默认规则
    if (g_config.config_file) {
        if (xpac_load_config(g_config.config_file) == 0) {
            printf("[PAC] 已从配置文件加载域名规则: %s\n", g_config.config_file);
        } else {
            printf("[PAC] 未找到配置文件或配置文件为空: %s，使用内置默认规则\n",
                   g_config.config_file);
            xpac_load_builtin_config();
        }
    } else {
        xpac_load_builtin_config();
    }

    g_initialized = 1;
}

// 释放资源
void xpac_uninit(void) {
    xpac_clear_domains();
    free_allow_ip_list();
    g_allow_ip_list = NULL;
    g_allow_ip_count = 0;
    free_bulk_domain_list();
    g_bulk_domain_list = NULL;
    g_bulk_domain_count = 0;
}

// ===================== 配置文件管理 =====================
// 解析一行配置（会就地修改 line），成功添加一条规则返回 1，否则 0
static int parse_config_line(char* line, int line_num) {
    // 跳过空行和注释行
    char* trimmed = line;
    while (*trimmed && isspace((unsigned char)*trimmed)) trimmed++;
    if (*trimmed == '#' || *trimmed == ';' || *trimmed == '\0') {
        return 0;
    }

    // 移除行尾换行符和回车符
    char* newline = strchr(trimmed, '\n');
    if (newline) {
        *newline = '\0';
        if (newline > trimmed && *(newline - 1) == '\r') {
            *(newline - 1) = '\0';
        }
    }
    char* cr = strchr(trimmed, '\r');
    if (cr) *cr = '\0';

    if (strncmp(trimmed, "@allow", 6) == 0) {
        char ip[64];
        if (sscanf(trimmed + 6, "%63s", ip) == 1) {
            if (xpac_add_allow_ip(ip) == 0)
                return 1;
            printf("[PAC] 警告：第%d行白名单解析失败: %s\n", line_num, trimmed);
        } else {
            printf("[PAC] 警告：第%d行白名单格式无效: %s\n", line_num, trimmed);
        }
        return 0;
    }

    if (strncmp(trimmed, "@bulk", 5) == 0) {
        char domain[256];
        if (sscanf(trimmed + 5, "%255s", domain) == 1) {
            if (xpac_add_bulk_domain(domain) == 0)
                return 1;
            printf("[PAC] 警告：第%d行分流域名解析失败: %s\n", line_num, trimmed);
        } else {
            printf("[PAC] 警告：第%d行分流域名格式无效: %s\n", line_num, trimmed);
        }
        return 0;
    }

    // 解析格式：域名模式 代理类型
    char pattern[256];
    char type_str[32];
    int parsed = sscanf(trimmed, "%255s %31s", pattern, type_str);

    if (parsed == 2) {
        ProxyType proxy_type = parse_proxy_type(type_str);
        if (xpac_add_domain(pattern, proxy_type) == 0)
            return 1;
        printf("[PAC] 警告：第%d行解析失败: %s\n", line_num, trimmed);
    } else if (parsed == 1) {
        // 只指定域名，使用默认代理类型
        if (xpac_add_domain(pattern, PROXY_TYPE_HTTP) == 0)
            return 1;
    } else {
        printf("[PAC] 警告：第%d行格式无效: %s\n", line_num, trimmed);
    }
    return 0;
}

// exe 内置的默认 PAC 规则（与 pac_config.txt 同格式，注释行已去除；
// 更新预置规则时同步维护这里和 pac_config.txt）
static const char PAC_BUILTIN_CONFIG[] =
    "@bulk googlevideo.com\n"
    "@bulk c.youtube.com\n"
    "@bulk ytimg.com\n"
    "@bulk video.twimg.com\n"
    "@bulk tiktokcdn.com\n"
    "@bulk tiktokcdn-us.com\n"
    "@bulk nflxvideo.net\n"
    "@bulk download.amd.com\n"
    "huggingface.co socks5\n"
    "todesktop.com socks5\n"
    "cursor-cdn.com socks5\n"
    "cursor.sh socks5\n"
    "cursor.com socks5\n"
    "facebook.net socks5\n"
    "intellimizeio.com socks5\n"
    "anthropic.com socks5\n"
    "amplitude.com socks5\n"
    "unpkg.com socks5\n"
    "jsdelivr.net socks5\n"
    "cloudfront.net socks5\n"
    "intellimize.co socks5\n"
    "intercom.io socks5\n"
    "website-files.com socks5\n"
    "claude.com socks5\n"
    "claude.ai socks5\n"
    "android.com socks5\n"
    "truthsocial.com socks5\n"
    "manus.im socks5\n"
    "ytimg.com socks5\n"
    "cdninstagram.com socks5\n"
    "instagram.com socks5\n"
    "telegram.org socks5\n"
    "telegram5.org socks5\n"
    "telegramjq.com socks5\n"
    "discord.com socks5\n"
    "discord.gg socks5\n"
    "reddit.com socks5\n"
    "redd.it socks5\n"
    "redditmedia.com socks5\n"
    "redditstatic.com socks5\n"
    "redditspace.com socks5\n"
    "googletagmanager.com socks5\n"
    "google.com socks5\n"
    "antigravity.google socks5\n"
    "google-analytics.com socks5\n"
    "googleapis.com socks5\n"
    "googlecode.com socks5\n"
    "googleearth.com socks5\n"
    "panoramio.com socks5\n"
    "googlevideo.com socks5\n"
    "googleusercontent.com socks5\n"
    "1e100.net socks5\n"
    "ggpht.com socks5\n"
    "oaistatic.com socks5\n"
    "cloudflare.com socks5\n"
    "chatgpt.com socks5\n"
    "openai.com socks5\n"
    "gmail.com socks5\n"
    "gstatic.com socks5\n"
    "wikipedia.org socks5\n"
    "sf.net socks5\n"
    "sourceforge.net socks5\n"
    "githubusercontent.com socks5\n"
    "github.io socks5\n"
    "github.com socks5\n"
    "githubassets.com socks5\n"
    "githubcopilot.com socks5\n"
    "typora.io socks5\n"
    "x.com socks5\n"
    "twitter.com socks5\n"
    "pscp.tv socks5\n"
    "twimg.com socks5\n"
    "hcaptcha.com socks5\n"
    "ollama.com socks5\n"
    "hubspot.com socks5\n"
    "youtube.com socks5\n"
    "youtube-nocookie.com socks5\n"
    "lunarg.com socks5\n"
    "withgoogle.com socks5\n"
    "yunduanshin.net socks5\n"
    "cryptomus.com socks5\n"
    "tiktokv.us socks5\n"
    "tiktokcdn-us.com socks5\n"
    "tiktokv.com socks5\n"
    "tiktokw.com socks5\n"
    "tiktokcdn.com socks5\n"
    "tiktok.com socks5\n"
    "facebook.com socks5\n"
    "amazon.com socks5\n"
    "tabbit.ai socks5\n"
;

// 加载 exe 内置的默认规则。
// 仅在外部配置文件缺失/无效时调用；规则列表不落盘，直到用户第一次
// 添加/删除触发 xpac_save_config 才写出到外部文件。
static int xpac_load_builtin_config(void) {
    char line[512];
    const char* p = PAC_BUILTIN_CONFIG;
    int line_num = 0;
    int success_count = 0;

    while (*p) {
        const char* nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        line_num++;
        success_count += parse_config_line(line, line_num);
        p = nl ? nl + 1 : p + len;
    }

    printf("[PAC] 已加载内置默认规则：%d 条规则，%d 个分流域名\n",
           success_count, g_bulk_domain_count);
    return (success_count > 0) ? 0 : -1;
}

static int xpac_load_config(const char* filename) {
    if (!filename) {
        printf("[PAC] 错误：配置文件路径为空\n");
        return -1;
    }

    printf("[PAC] 加载配置文件: %s\n", filename);
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        printf("[PAC] 无法打开配置文件: %s (错误: %s)\n", filename, strerror(errno));
        return -1;
    }

    // 保存旧列表以便出错时恢复
    DomainRule* old_list = g_domain_list;
    int old_count = g_domain_count;
    AllowIpRule* old_allow_list = g_allow_ip_list;
    int old_allow_count = g_allow_ip_count;
    BulkDomainRule* old_bulk_list = g_bulk_domain_list;
    int old_bulk_count = g_bulk_domain_count;

    // 清空当前列表
    g_domain_list = NULL;
    g_domain_count = 0;
    g_allow_ip_list = NULL;
    g_allow_ip_count = 0;
    g_bulk_domain_list = NULL;
    g_bulk_domain_count = 0;

    char line[512];
    int line_num = 0;
    int success_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        success_count += parse_config_line(line, line_num);
    }

    fclose(fp);

    if (success_count == 0) {
        // 恢复旧列表
        free_domain_list();
        g_domain_list = old_list;
        g_domain_count = old_count;
        free_allow_ip_list();
        g_allow_ip_list = old_allow_list;
        g_allow_ip_count = old_allow_count;
        free_bulk_domain_list();
        g_bulk_domain_list = old_bulk_list;
        g_bulk_domain_count = old_bulk_count;
        printf("[PAC] 配置文件未包含有效规则: %s\n", filename);
        return -1;
    } else {
        // 释放旧列表
        DomainRule* current = old_list;
        while (current) {
            DomainRule* next = current->next;
            free(current);
            current = next;
        }
        AllowIpRule* allow_current = old_allow_list;
        while (allow_current) {
            AllowIpRule* next = allow_current->next;
            free(allow_current);
            allow_current = next;
        }
        BulkDomainRule* bulk_current = old_bulk_list;
        while (bulk_current) {
            BulkDomainRule* next = bulk_current->next;
            free(bulk_current);
            bulk_current = next;
        }
        printf("[PAC] 成功从配置文件加载 %d 条规则，%d 个白名单IP，%d 个分流域名: %s\n",
               success_count, g_allow_ip_count, g_bulk_domain_count, filename);
        return 0;
    }
}

static int xpac_save_config(const char* filename) {
    if (!filename) {
        if (!g_config.config_file) {
            printf("[PAC] 错误：未指定配置文件路径\n");
            return -1;
        }
        filename = g_config.config_file;
    }

    // 确保目录存在
    char dir_path[512];
    strncpy(dir_path, filename, sizeof(dir_path) - 1);
    char* last_slash = strrchr(dir_path, PATH_SEPARATOR);
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir_path);
    }

    FILE* fp = fopen(filename, "w");
    if (!fp) {
        printf("[PAC] 无法创建配置文件: %s\n", filename);
        return -1;
    }

    fprintf(fp, "# PAC域名规则配置文件\n");
    fprintf(fp, "# 格式：域名 代理类型(http/socks5)，存裸域名（子域名/后缀匹配由PAC生成时派生）\n");
    fprintf(fp, "# 示例：google.com socks5\n");
    fprintf(fp, "#        github.com http\n");
    fprintf(fp, "# 兼容旧格式：*.google.com 会自动剥掉 \"*.\" 前缀\n");
    fprintf(fp, "# 白名单格式：@allow 1.2.3.4\n");
    fprintf(fp, "# 大流量分流：@bulk googlevideo.com（命中域名走独立SSH会话）\n");
    fprintf(fp, "\n");

    AllowIpRule* allow = g_allow_ip_list;
    while (allow) {
        fprintf(fp, "@allow %s\n", allow->ip);
        allow = allow->next;
    }
    if (g_allow_ip_count > 0) {
        fprintf(fp, "\n");
    }

    BulkDomainRule* bulk = g_bulk_domain_list;
    while (bulk) {
        fprintf(fp, "@bulk %s\n", bulk->domain);
        bulk = bulk->next;
    }
    if (g_bulk_domain_count > 0) {
        fprintf(fp, "\n");
    }

    DomainRule* current = g_domain_list;
    while (current) {
        fprintf(fp, "%s %s\n",
                current->pattern,
                proxy_type_to_str(current->proxy_type));
        current = current->next;
    }

    fclose(fp);
    printf("[PAC] 成功保存 %d 条规则，%d 个白名单IP，%d 个分流域名到配置文件: %s\n",
           g_domain_count, g_allow_ip_count, g_bulk_domain_count, filename);
    return 0;
}

// ===================== 域名管理API =====================
/* 规则以裸域名存储（如 "google.com"），PAC 生成时再派生全部匹配形态。
** 这里剥掉旧格式的 "*." / "." 前缀，让旧配置文件和 "*.google.com" 这类
** 输入自动迁移，并与 "google.com" 归一到同一条规则。"*"（全匹配）原样保留。 */
static void xpac_normalize_pattern(const char* pattern, char* out, size_t out_size) {
    const char* p = pattern ? pattern : "";
    if (strcmp(p, "*") != 0) {
        if (p[0] == '*' && p[1] == '.') p += 2;
        while (p[0] == '.') p++;
    }
    snprintf(out, out_size, "%s", p);
}

static int xpac_add_domain(const char* pattern, ProxyType proxy_type) {
    if (!pattern || !pattern[0]) {
        printf("[PAC] 错误：域名模式为空\n");
        return -1;
    }

    char formatted_pattern[256] = {0};
    xpac_normalize_pattern(pattern, formatted_pattern, sizeof(formatted_pattern));
    if (strcmp(formatted_pattern, pattern) != 0) {
        printf("[PAC] 格式化域名: %s -> %s\n", pattern, formatted_pattern);
    }

    // 验证格式化后的域名
    if (!is_valid_domain_pattern(formatted_pattern)) {
        printf("[PAC] 错误：格式化后的域名无效: %s\n", formatted_pattern);
        return -1;
    }

    // 检查是否已存在
    DomainRule* existing = find_domain_rule(formatted_pattern);
    if (existing) {
        printf("[PAC] 域名规则已存在: %s -> %s\n",
               pattern, proxy_type_to_str(existing->proxy_type));
        existing->proxy_type = proxy_type; // 更新代理类型
        return 0;
    }

    // 创建新规则
    DomainRule* new_rule = (DomainRule*)malloc(sizeof(DomainRule));
    if (!new_rule) {
        printf("[PAC] 错误：内存分配失败\n");
        return -1;
    }

    strncpy(new_rule->pattern, formatted_pattern, sizeof(new_rule->pattern) - 1);
    new_rule->pattern[sizeof(new_rule->pattern) - 1] = '\0';
    new_rule->proxy_type = proxy_type;
    new_rule->next = NULL;

    // 添加到链表头部
    new_rule->next = g_domain_list;
    g_domain_list = new_rule;
    g_domain_count++;

    XLOGI("[PAC] 添加域名规则: %s -> %s\n",
           pattern, proxy_type_to_str(proxy_type));

    // 自动保存到配置文件（如果配置了）
    if (g_config.config_file && g_initialized)
        xpac_save_config(g_config.config_file);

    return 0;
}

static int xpac_remove_domain(const char* pattern) {
    if (!pattern || !pattern[0]) {
        printf("[PAC] 错误：域名模式为空\n");
        return -1;
    }

    /* 接受裸域名和旧的 "*." 格式，统一归一后再查找 */
    char formatted_pattern[256] = {0};
    xpac_normalize_pattern(pattern, formatted_pattern, sizeof(formatted_pattern));

    DomainRule* prev = NULL;
    DomainRule* current = g_domain_list;

    while (current) {
        if (strcmp(current->pattern, formatted_pattern) == 0) {
            if (prev) {
                prev->next = current->next;
            } else {
                g_domain_list = current->next;
            }

            printf("[PAC] 删除域名规则: %s -> %s\n",
                   pattern, proxy_type_to_str(current->proxy_type));

            free(current);
            g_domain_count--;

            // 自动保存到配置文件
            if (g_config.config_file && g_initialized) {
                xpac_save_config(g_config.config_file);
            }

            return 0;
        }

        prev = current;
        current = current->next;
    }

    printf("[PAC] 未找到域名规则: %s\n", pattern);
    return -1;
}

static int is_valid_ipv4_address(const char* ip) {
    struct sockaddr_in addr;
    return ip && inet_pton(AF_INET, ip, &addr.sin_addr) == 1;
}

static int xpac_add_allow_ip(const char* ip) {
    if (!is_valid_ipv4_address(ip)) {
        printf("[PAC] 错误：白名单IP无效: %s\n", ip ? ip : "");
        return -1;
    }

    if (find_allow_ip_rule(ip)) {
        printf("[PAC] 白名单IP已存在: %s\n", ip);
        return 0;
    }

    AllowIpRule* rule = (AllowIpRule*)malloc(sizeof(AllowIpRule));
    if (!rule) {
        printf("[PAC] 错误：白名单内存分配失败\n");
        return -1;
    }

    strncpy(rule->ip, ip, sizeof(rule->ip) - 1);
    rule->ip[sizeof(rule->ip) - 1] = '\0';
    rule->next = g_allow_ip_list;
    g_allow_ip_list = rule;
    g_allow_ip_count++;

    XLOGI("[PAC] 添加代理白名单IP: %s", ip);
    if (g_config.config_file && g_initialized)
        xpac_save_config(g_config.config_file);

    return 0;
}

static int xpac_remove_allow_ip(const char* ip) {
    if (!ip || !ip[0]) {
        printf("[PAC] 错误：白名单IP为空\n");
        return -1;
    }

    AllowIpRule* prev = NULL;
    AllowIpRule* current = g_allow_ip_list;
    while (current) {
        if (strcmp(current->ip, ip) == 0) {
            if (prev) {
                prev->next = current->next;
            } else {
                g_allow_ip_list = current->next;
            }
            free(current);
            g_allow_ip_count--;
            XLOGI("[PAC] 删除代理白名单IP: %s", ip);
            if (g_config.config_file && g_initialized)
                xpac_save_config(g_config.config_file);
            return 0;
        }
        prev = current;
        current = current->next;
    }

    printf("[PAC] 未找到白名单IP: %s\n", ip);
    return -1;
}

static BulkDomainRule* find_bulk_domain_rule(const char* domain) {
    BulkDomainRule* current = g_bulk_domain_list;
    while (current) {
        if (strcasecmp(current->domain, domain) == 0)
            return current;
        current = current->next;
    }
    return NULL;
}

static int xpac_add_bulk_domain(const char* domain) {
    if (!domain || !domain[0]) {
        printf("[PAC] 错误：分流域名为空\n");
        return -1;
    }

    char normalized[256] = {0};
    xpac_normalize_pattern(domain, normalized, sizeof(normalized));
    if (!is_valid_domain_pattern(normalized) || strcmp(normalized, "*") == 0) {
        printf("[PAC] 错误：分流域名无效: %s\n", domain);
        return -1;
    }

    if (find_bulk_domain_rule(normalized)) {
        printf("[PAC] 分流域名已存在: %s\n", normalized);
        return 0;
    }

    BulkDomainRule* rule = (BulkDomainRule*)malloc(sizeof(BulkDomainRule));
    if (!rule) {
        printf("[PAC] 错误：分流域名内存分配失败\n");
        return -1;
    }

    strncpy(rule->domain, normalized, sizeof(rule->domain) - 1);
    rule->domain[sizeof(rule->domain) - 1] = '\0';
    rule->next = g_bulk_domain_list;
    g_bulk_domain_list = rule;
    g_bulk_domain_count++;

    XLOGI("[PAC] 添加大流量分流域名: %s", normalized);
    return 0;
}

static void free_bulk_domain_list(void) {
    BulkDomainRule* current = g_bulk_domain_list;
    while (current) {
        BulkDomainRule* next = current->next;
        free(current);
        current = next;
    }
}

/* host 是否命中 @bulk 分流域名：等于该域名，或以 ".域名" 结尾。 */
int xpac_is_bulk_domain(const char* host) {
    if (!host || !host[0]) return 0;
    size_t hlen = strlen(host);
    BulkDomainRule* rule = g_bulk_domain_list;
    while (rule) {
        size_t dlen = strlen(rule->domain);
        if (dlen > 0 && dlen <= hlen) {
            const char* tail = host + (hlen - dlen);
            if (strcasecmp(tail, rule->domain) == 0 &&
                (hlen == dlen || tail[-1] == '.')) {
                return 1;
            }
        }
        rule = rule->next;
    }
    return 0;
}

static void xpac_clear_domains(void) {
    free_domain_list();
    g_domain_list = NULL;
    g_domain_count = 0;
    printf("[PAC] 已清空所有域名规则\n");
}

// ===================== 工具函数 =====================
static DomainRule* find_domain_rule(const char* pattern) {
    DomainRule* current = g_domain_list;
    while (current) {
        if (strcmp(current->pattern, pattern) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

static AllowIpRule* find_allow_ip_rule(const char* ip) {
    AllowIpRule* current = g_allow_ip_list;
    while (current) {
        if (strcmp(current->ip, ip) == 0)
            return current;
        current = current->next;
    }
    return NULL;
}

static void free_domain_list(void) {
    DomainRule* current = g_domain_list;
    while (current) {
        DomainRule* next = current->next;
        free(current);
        current = next;
    }
}

static void free_allow_ip_list(void) {
    AllowIpRule* current = g_allow_ip_list;
    while (current) {
        AllowIpRule* next = current->next;
        free(current);
        current = next;
    }
}

int xpac_proxy_client_allowed(const char* client_ip) {
    if (!g_config.enable_proxy_whitelist) return 1;
    if (!client_ip || !client_ip[0]) return 0;
    if (strcmp(client_ip, "127.0.0.1") == 0 || strcmp(client_ip, "localhost") == 0)
        return 1;
    return find_allow_ip_rule(client_ip) != NULL;
}

static int is_valid_domain_pattern(const char* pattern) {
    if (!pattern || strlen(pattern) > 255) {
        return 0;
    }

    // 检查基本格式：可以包含字母、数字、点、星号、连字符
    for (int i = 0; pattern[i]; i++) {
        char c = pattern[i];
        if (!(isalnum((unsigned char)c) || c == '.' || c == '*' || c == '-' || c == '_')) {
            return 0;
        }
    }

    // 检查是否至少包含一个点（"*" 全匹配除外）
    if (strchr(pattern, '.') == NULL && strcmp(pattern, "*") != 0) {
        return 0;
    }

    return 1;
}

/* 是否为纯 IPv4 字面量（四段十进制，每段 0-255）。这类规则在生成 PAC 时不派生
** 子域名/后缀形态：PAC 的 host 是 URL 里的字面主机名，IP 只可能精确相等，而派生
** 出的 "1.2.3.4.*" 会误伤 nip.io / sslip.io 这类通配DNS域名。 */
static int is_ipv4_literal(const char* s) {
    if (!s) return 0;

    for (int seg = 0; seg < 4; seg++) {
        int val = 0, digits = 0;

        if (!isdigit((unsigned char)*s)) return 0;
        while (isdigit((unsigned char)*s)) {
            val = val * 10 + (*s++ - '0');
            if (++digits > 3 || val > 255) return 0;
        }

        if (seg < 3) {
            if (*s++ != '.') return 0;
        } else if (*s != '\0') {
            return 0;
        }
    }

    return 1;
}

static int parse_proxy_type(const char* type_str) {
    if (!type_str) return PROXY_TYPE_HTTP;

    if (strcasecmp(type_str, "socks5") == 0 || strcasecmp(type_str, "socks") == 0) {
        return PROXY_TYPE_SOCKS5;
    } else if (strcasecmp(type_str, "auto") == 0) {
        return PROXY_TYPE_AUTO;
    }

    return PROXY_TYPE_HTTP; // 默认
}

static const char* proxy_type_to_str(ProxyType type) {
    switch (type) {
        case PROXY_TYPE_SOCKS5: return "socks5";
        case PROXY_TYPE_AUTO:   return "auto";
        case PROXY_TYPE_HTTP:   // 默认
        default:                return "http";
    }
}

// ===================== PAC生成API =====================
static const char* get_pac_proxy_address(void) {
    static char address[256] = "127.0.0.1";

    if (g_config.proxy_host && g_config.proxy_host[0] != '\0') {
        strncpy(address, g_config.proxy_host, sizeof(address) - 1);
        address[sizeof(address) - 1] = '\0';
        return address;
    }

    if (!g_config.bind_address || g_config.bind_address[0] == '\0')
        return address;

    if (strcmp(g_config.bind_address, "0.0.0.0") != 0) {
        strncpy(address, g_config.bind_address, sizeof(address) - 1);
        address[sizeof(address) - 1] = '\0';
        return address;
    }

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent* he = gethostbyname(hostname);
        if (he && he->h_addr_list[0]) {
            const char* result = inet_ntop(AF_INET, he->h_addr_list[0], address, sizeof(address));
            if (result) return address;
        }
    }

    return address;
}

// 生成PAC文件内容（根据类型）
// 注意：返回的字符串需要调用者释放
static char* xpac_generate_pac_content(int pac_type) {
    // 计算需要的缓冲区大小
    int buffer_size = 2048; // 基础大小
    DomainRule* current = g_domain_list;

    // 为域名规则预留空间（每条规则展开为4个shExpMatch条件）
    while (current) {
        buffer_size += 256 + 4 * (int)strlen(current->pattern);
        current = current->next;
    }

    char* pac_content = (char*)malloc(buffer_size);
    if (!pac_content) return NULL;

    const char* ip = get_pac_proxy_address();
    int pos = 0;

    // PAC文件头部
    pos += snprintf(pac_content + pos, buffer_size - pos,
        "function FindProxyForURL(url, host) {\n"
        "    // 自动生成的PAC文件\n"
        "    // 本地地址直连\n"
        "    if (isPlainHostName(host) ||\n"
        "        shExpMatch(host, \"localhost\") ||\n"
        "        shExpMatch(host, \"127.*\") ||\n"
        "        shExpMatch(host, \"192.168.*\")) {\n"
        "        return \"DIRECT\";\n"
        "    }\n");

    // 添加域名规则
    current = g_domain_list;
    if (current && pac_type==1) {
        pos += snprintf(pac_content + pos, buffer_size - pos,
            "\n    // 自定义域名规则\n");

        /*
         * 规则只在 proxy.pac 里生成（见上面的 pac_type==1），而 proxy.pac 同时
         * 要给 Windows 系统代理用：WinINET 会丢弃 PAC 返回的 SOCKS5 结果，所以
         * 无论规则本身标的是 socks5/http/auto，一律返回 PROXY:http_proxy_port，
         * 由 HTTP 代理内部再转发到 SOCKS5。
         */
        const char* proxy_str = "PROXY";
        int port = g_config.http_proxy_port;

        while (current) {
            // 生成域名匹配条件：规则存裸域名 X，这里派生全部匹配形态——
            // 子域名、X 本身、以及带额外后缀的形态（如 google.com.hk /
            // www.google.com.hk）。"*"（全匹配）和 IP 字面量按原样精确匹配。
            if (strcmp(current->pattern, "*") != 0 && !is_ipv4_literal(current->pattern)) {
                const char* bare = current->pattern;
                pos += snprintf(pac_content + pos, buffer_size - pos,
                    "    if (shExpMatch(host, \"*.%s\") ||\n"
                    "        shExpMatch(host, \"%s\") ||\n"
                    "        shExpMatch(host, \"%s.*\") ||\n"
                    "        shExpMatch(host, \"*.%s.*\")) {\n"
                    "        return \"%s %s:%d\";\n"
                    "    }\n",
                    bare, bare, bare, bare, proxy_str, ip, port);
            } else {
                pos += snprintf(pac_content + pos, buffer_size - pos,
                    "    if (shExpMatch(host, \"%s\")) {\n"
                    "        return \"%s %s:%d\";\n"
                    "    }\n",
                    current->pattern, proxy_str, ip, port);
            }
            current = current->next;
        }
    }

    // PAC文件尾部
    if (pac_type == 3) { // proxy.http.pac，强制所有流量走代理
        pos += snprintf(pac_content + pos, buffer_size - pos,
            "\n    // 所有流量走HTTP代理\n"
            "    return \"PROXY %s:%d\";\n",
            ip, g_config.http_proxy_port);
    } else if (pac_type == 2) { // proxy.socks5.pac，默认SOCKS5
        /*
         * 回落用本机HTTP代理，不用SOCKS(=SOCKS4)：socks5_server 只接受
         * 版本字节 0x05，SOCKS4 握手必被拒，且 SOCKS4 只能本地解析DNS。
         * HTTP代理这一跳内部仍然转发到 SOCKS5，语义一致。
         */
        pos += snprintf(pac_content + pos, buffer_size - pos,
            "\n    // 所有流量走SOCKS5代理，SOCKS5不可用时回落到本机HTTP代理\n"
            "    return \"SOCKS5 %s:%d; PROXY %s:%d\";\n",
            ip, g_config.socks5_proxy_port, ip, g_config.http_proxy_port);
    } else { // proxy.pac，默认HTTP代理
        pos += snprintf(pac_content + pos, buffer_size - pos,
                    "\n    // 所有其他不走代理直接访问\n"
                    "    return \"DIRECT\";\n");
    }

    pos += snprintf(pac_content + pos, buffer_size - pos, "}\n");

    // 确保字符串正确终止
    pac_content[pos] = '\0';

    return pac_content;
}

// ===================== HTTP请求处理 =====================
static int is_pac_request(const char* req_buf, int req_len) {
    if (!req_buf || req_len <= 0) return 0;

    // 检查请求行
    if (strncmp(req_buf, "GET /", 5) != 0)
        return 0; // 不是GET请求
    if (req_len >= 14 && strncmp(req_buf + 5, "proxy.pac", 9) == 0)
        return 1; // proxy.pac request
    if (req_len >= 21 && strncmp(req_buf + 5, "proxy.socks5.pac", 16) == 0)
        return 2; // proxy.socks5.pac
    if (req_len >= 19 && strncmp(req_buf + 5, "proxy.http.pac", 14) == 0)
        return 3; // proxy.http.pac

    return 0;
}

static int is_admin_request(const char* req_buf, int req_len) {
    if (!req_buf || req_len <= 0) return 0;

    // 检查是否为GET请求（至少需要5字节 "GET /"）
    if (req_len < 5 || memcmp(req_buf, "GET /", 5) != 0)
        return 0; // 不是GET请求

    // API端点检查（需要至少20字节 "GET /admin/api/..."）
    if (req_len >= 20 && memcmp(req_buf + 5, "admin/api/", 10) == 0) {
        const char* api_path = req_buf + 15; // 跳过 "admin/api/" 共10个字符

        // 确保api_path在缓冲区范围内
        if (api_path - req_buf >= req_len) {
            return 0;
        }

        // 计算剩余长度
        int remaining = req_len - (api_path - req_buf);

        if (remaining >= 7 && memcmp(api_path, "domains", 7) == 0) {
            // 检查是否是完整的 "domains"（后面是空格、问号、斜杠或字符串结束）
            if (remaining == 7 || api_path[7] == ' ' || api_path[7] == '?' || api_path[7] == '/') {
                return 2; // GET /admin/api/domains
            }
        }

        if (remaining >= 3 && memcmp(api_path, "add", 3) == 0) {
            if (remaining == 3 || api_path[3] == ' ' || api_path[3] == '?' || api_path[3] == '/') {
                return 3; // GET /admin/api/add
            }
        }

        if (remaining >= 6 && memcmp(api_path, "remove", 6) == 0) {
            if (remaining == 6 || api_path[6] == ' ' || api_path[6] == '?' || api_path[6] == '/') {
                return 4; // GET /admin/api/remove
            }
        }

        if (remaining >= 6 && memcmp(api_path, "status", 6) == 0) {
            if (remaining == 6 || api_path[6] == ' ' || api_path[6] == '?' || api_path[6] == '/') {
                return 5; // GET /admin/api/status
            }
        }

        if (remaining >= 9 && memcmp(api_path, "whitelist", 9) == 0) {
            if (remaining == 9 || api_path[9] == ' ' || api_path[9] == '?' || api_path[9] == '/') {
                return 6; // GET /admin/api/whitelist
            }
        }

        if (remaining >= 9 && memcmp(api_path, "allow-add", 9) == 0) {
            if (remaining == 9 || api_path[9] == ' ' || api_path[9] == '?' || api_path[9] == '/') {
                return 7; // GET /admin/api/allow-add
            }
        }

        if (remaining >= 12 && memcmp(api_path, "allow-remove", 12) == 0) {
            if (remaining == 12 || api_path[12] == ' ' || api_path[12] == '?' || api_path[12] == '/') {
                return 8; // GET /admin/api/allow-remove
            }
        }
    }

    // 管理界面检查（需要至少11字节 "GET /admin"）
    if (req_len >= 11 && memcmp(req_buf + 5, "admin", 5) == 0) {
        // 检查是否是/admin或/admin/（注意：req_buf + 5 跳过了 "GET /"，所以指向 "admin..."）
        const char* after_admin = req_buf + 10; // 跳过 "admin" 共5个字符
        if (after_admin - req_buf < req_len &&
            (after_admin[0] == ' ' || after_admin[0] == '?' || after_admin[0] == '/')) {
            return 1; // 管理界面首页
        }
    }

    // 根路径检查：GET / 或 GET /?... 直接返回管理界面
    // 请求格式: "GET / " 或 "GET /?xxx" 或 "GET /HTTP"
    if (req_len >= 6 && req_buf[4] == '/') {
        char next_char = req_buf[5];
        // 如果 / 后面是空格、问号或者是 HTTP 协议，说明是根路径
        if (next_char == ' ' || next_char == '?' ||
            (req_len >= 8 && strncmp(req_buf + 5, "HTTP/", 5) == 0)) {
            return 1; // 根路径返回管理界面
        }
    }
    return 0;
}

// ===================== HTTP响应函数 =====================
static void send_http_response(SOCKET_T client_sock, const char* content_type,
                              const char* body, int body_len) {
    char header[512];
    snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "Pragma: no-cache\r\n"
        "Expires: 0\r\n"
        "\r\n",
        content_type, body_len);

    send(client_sock, header, strlen(header), 0);
    if (body && body_len > 0) {
        send(client_sock, body, body_len, 0);
    }
}

static void send_json_response(SOCKET_T client_sock, const char* json) {
    send_http_response(client_sock, "application/json", json, strlen(json));
}

static void send_html_response(SOCKET_T client_sock, const char* html) {
    send_http_response(client_sock, "text/html; charset=utf-8", html, strlen(html));
}

static void send_pac_response(SOCKET_T client_sock, const char* pac_content) {
    send_http_response(client_sock, "application/x-ns-proxy-autoconfig",
                       pac_content, strlen(pac_content));
}

static void send_error_response(SOCKET_T client_sock, int code, const char* message) {
    char body[256];
    snprintf(body, sizeof(body),
        "<html><head><title>Error %d</title></head>\n"
        "<body><h1>Error %d</h1><p>%s</p></body></html>",
        code, code, message);

    char header[512];
    snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        code, message, (int)strlen(body));

    send(client_sock, header, strlen(header), 0);
    send(client_sock, body, strlen(body), 0);
}

static void send_auth_required_response(SOCKET_T client_sock) {
    const char* body = "<html><body><h1>401 Unauthorized</h1></body></html>";
    char header[512];

    snprintf(header, sizeof(header),
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: Basic realm=\"xproxy admin\"\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        (int)strlen(body));

    send(client_sock, header, strlen(header), 0);
    send(client_sock, body, strlen(body), 0);
}

static int base64_value(char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    if (ch == '=') return -2;
    return -1;
}

static int base64_decode(const char* src, unsigned char* dst, int dst_len) {
    int out = 0;
    int val = 0;
    int bits = -8;

    while (*src && *src != '\r' && *src != '\n') {
        int c = base64_value(*src++);
        if (c == -2) break;
        if (c < 0) return -1;
        val = (val << 6) | c;
        bits += 6;
        if (bits >= 0) {
            if (out >= dst_len) return -1;
            dst[out++] = (unsigned char)((val >> bits) & 0xFF);
            bits -= 8;
        }
    }

    return out;
}

static const char* find_header_value(const char* req_buf, int req_len, const char* header_name) {
    const char* p = req_buf;
    const char* end = req_buf + req_len;
    size_t name_len = strlen(header_name);

    while (p < end) {
        const char* line_end = strstr(p, "\r\n");
        if (!line_end || line_end > end) break;
        if (line_end == p) break;

        if ((size_t)(line_end - p) > name_len &&
            strncasecmp(p, header_name, name_len) == 0 &&
            p[name_len] == ':') {
            p += name_len + 1;
            while (p < line_end && (*p == ' ' || *p == '\t')) p++;
            return p;
        }

        p = line_end + 2;
    }

    return NULL;
}

static int admin_auth_ok(const char* req_buf, int req_len) {
    const char* user = g_config.admin_username;
    const char* pass = g_config.admin_password;
    if (!pass || pass[0] == '\0') return 1;
    if (!user || user[0] == '\0') user = "admin";

    const char* auth = find_header_value(req_buf, req_len, "Authorization");
    if (!auth || strncasecmp(auth, "Basic ", 6) != 0) return 0;

    unsigned char decoded[512];
    int decoded_len = base64_decode(auth + 6, decoded, sizeof(decoded) - 1);
    if (decoded_len <= 0) return 0;
    decoded[decoded_len] = '\0';

    char expected[512];
    snprintf(expected, sizeof(expected), "%s:%s", user, pass);
    return strcmp((const char*)decoded, expected) == 0;
}

static void url_decode(const char* src, char* dst, int dst_len) {
    int i = 0, j = 0;
    while (src[i] && j < dst_len - 1) {
        if (src[i] == '%' && isxdigit((unsigned char)src[i+1])
                          && isxdigit((unsigned char)src[i+2])) {
            char hex[3] = { src[i+1], src[i+2], '\0' };
            dst[j++] = (char)strtol(hex, NULL, 16);
            i += 3;
        } else if (src[i] == '+') {
            dst[j++] = ' ';
            i++;
        } else {
            dst[j++] = src[i++];
        }
    }
    dst[j] = '\0';
}

// 从查询字符串中提取参数
static const char* get_query_param(const char* query_str, const char* key,
                                  char* buffer, int buf_len) {
    if (!query_str || !key || !buffer || buf_len <= 0) return NULL;

    char search_key[256];
    snprintf(search_key, sizeof(search_key), "%s=", key);

    const char* pos = strstr(query_str, search_key);
    if (!pos) return NULL;

    pos += strlen(search_key);
    int i = 0;
    while (pos[i] && pos[i] != '&' && pos[i] != ' ' && i < buf_len - 1) {
        buffer[i] = pos[i];
        i++;
    }
    buffer[i] = '\0';

    char decoded[256];
    url_decode(buffer, decoded, sizeof(decoded));
    snprintf(buffer, buf_len, "%s", decoded);
    return buffer;
}

// 生成管理界面HTML
static const char* generate_admin_html(void) {
    static char html[42000];

    // 调试输出
    printf("[PAC-DEBUG] generate_admin_html: http_port=%d, socks5_port=%d, domain_count=%d\n",
           g_config.http_proxy_port, g_config.socks5_proxy_port, g_domain_count);
    printf("[PAC-DEBUG] domain_list=%p, domain_rows will be generated\n", (void*)g_domain_list);

    // 生成域名规则表格行
    static char domain_rows[20480] = {0};
    DomainRule* current = g_domain_list;
    int pos = 0;
    int row_count = 0;

    while (current && pos < sizeof(domain_rows) - 100) {
        pos += snprintf(domain_rows + pos, sizeof(domain_rows) - pos,
            "<tr>\n"
            "  <td><code>%s</code></td>\n"
            "  <td>%s</td>\n"
            "  <td>\n"
            "    <button onclick=\"removeDomain('%s')\" class=\"btn-delete\">删除</button>\n"
            "  </td>\n"
            "</tr>\n",
            current->pattern,
            proxy_type_to_str(current->proxy_type),
            current->pattern);
        current = current->next;
        row_count++;
    }

    printf("[PAC-DEBUG] Generated %d domain rows, buffer used: %d bytes\n", row_count, pos);

    if (pos == 0) {
        strcpy(domain_rows,
            "<tr><td colspan=\"3\" style=\"text-align: center;\">暂无域名规则</td></tr>\n");
        printf("[PAC-DEBUG] No domain rules found\n");
    }

    static char whitelist_rows[8192] = {0};
    AllowIpRule* allow_current = g_allow_ip_list;
    int allow_pos = 0;
    int allow_row_count = 0;
    while (allow_current && allow_pos < sizeof(whitelist_rows) - 100) {
        allow_pos += snprintf(whitelist_rows + allow_pos,
            sizeof(whitelist_rows) - allow_pos,
            "<tr>\n"
            "  <td><code>%s</code></td>\n"
            "  <td>\n"
            "    <button onclick=\"removeAllowIp('%s')\" class=\"btn-delete\">删除</button>\n"
            "  </td>\n"
            "</tr>\n",
            allow_current->ip,
            allow_current->ip);
        allow_current = allow_current->next;
        allow_row_count++;
    }
    if (allow_pos == 0) {
        strcpy(whitelist_rows,
            "<tr><td colspan=\"2\" style=\"text-align: center;\">暂无白名单IP，启用后仅允许本机内部转发</td></tr>\n");
    }

    // 完整的HTML页面
    // 注意：模板中有5个数值占位符：
    // 1. HTTP代理端口（统计框）
    // 2. SOCKS5代理端口（统计框）
    // 3. 域名规则数（统计框）← 这里应该是 g_domain_count
    // 4. HTTP代理端口（下拉框）
    // 5. SOCKS5代理端口（下拉框）
    snprintf(html, sizeof(html),
        "<!DOCTYPE html>\n"
        "<html lang=\"zh-CN\">\n"
        "<head>\n"
        "    <meta charset=\"utf-8\">\n"
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "    <title>PAC域名管理</title>\n"
        "    <style>\n"
        "        * { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; \n"
        "               line-height: 1.6; color: #333; background: #f5f5f5; padding: 20px; }\n"
        "        .container { max-width: 1200px; margin: 0 auto; background: white; \n"
        "                    border-radius: 8px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }\n"
        "        h1 { color: #2c3e50; margin-bottom: 20px; border-bottom: 2px solid #eee; padding-bottom: 10px; }\n"
        "        h2 { color: #3498db; margin: 25px 0 15px; }\n"
        "        .info-box { background: #f8f9fa; border-left: 4px solid #3498db; padding: 15px; margin: 20px 0; }\n"
        "        .info-box p { margin: 5px 0; }\n"
        "        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }\n"
        "        th, td { border: 1px solid #ddd; padding: 12px 15px; text-align: left; }\n"
        "        th { background: #f2f2f2; font-weight: 600; }\n"
        "        tr:nth-child(even) { background: #f9f9f9; }\n"
        "        code { background: #f1f1f1; padding: 2px 4px; border-radius: 3px; font-family: monospace; }\n"
        "        .form-group { margin-bottom: 15px; }\n"
        "        label { display: block; margin-bottom: 5px; font-weight: 500; }\n"
        "        input, select { width: 100%%; padding: 10px; border: 1px solid #ddd; \n"
        "                       border-radius: 4px; font-size: 14px; }\n"
        "        button { background: #3498db; color: white; border: none; padding: 10px 20px; \n"
        "                border-radius: 4px; cursor: pointer; font-size: 14px; }\n"
        "        button:hover { background: #2980b9; }\n"
        "        .btn-delete { background: #e74c3c; }\n"
        "        .btn-delete:hover { background: #c0392b; }\n"
        "        .btn-success { background: #27ae60; }\n"
        "        .btn-success:hover { background: #229954; }\n"
        "        .message { padding: 10px; margin: 10px 0; border-radius: 4px; }\n"
        "        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }\n"
        "        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }\n"
        "        .link-list { display: flex; gap: 15px; margin: 15px 0; }\n"
        "        .link-list a { color: #3498db; text-decoration: none; }\n"
        "        .link-list a:hover { text-decoration: underline; }\n"
        "        .stats { display: flex; gap: 20px; margin: 20px 0; }\n"
        "        .stat-box { flex: 1; background: #f8f9fa; padding: 15px; border-radius: 6px; }\n"
        "        .stat-value { font-size: 24px; font-weight: bold; color: #2c3e50; }\n"
        "        .stat-label { color: #666; font-size: 14px; }\n"
        "    </style>\n"
        "</head>\n"
        "<body>\n"
        "    <div class=\"container\">\n"
        "        <h1>📡 PAC域名管理</h1>\n"
        "        \n"
        "        <div class=\"stats\">\n"
        "            <div class=\"stat-box\">\n"
        "                <div class=\"stat-value\">%d</div>\n"
        "                <div class=\"stat-label\">HTTP代理端口</div>\n"
        "            </div>\n"
        "            <div class=\"stat-box\">\n"
        "                <div class=\"stat-value\">%d</div>\n"
        "                <div class=\"stat-label\">SOCKS5代理端口</div>\n"
        "            </div>\n"
        "            <div class=\"stat-box\">\n"
        "                <div class=\"stat-value\" id=\"domainCount\">%d</div>\n"
        "                <div class=\"stat-label\">域名规则数</div>\n"
        "            </div>\n"
        "        </div>\n"
        "        \n"
        "        <div class=\"info-box\">\n"
        "            <p><strong>PAC文件地址:</strong></p>\n"
        "            <div class=\"link-list\">\n"
        "                <a href=\"/proxy.pac\" target=\"_blank\">proxy.pac</a>\n"
        "                <a href=\"/proxy.socks5.pac\" target=\"_blank\">proxy.socks5.pac</a>\n"
        "                <a href=\"/proxy.http.pac\" target=\"_blank\">proxy.http.pac</a>\n"
        "            </div>\n"
        "            <p><small>将以上任意链接配置为浏览器的自动代理配置URL即可使用</small></p>\n"
        "        </div>\n"
        "        \n"
        "        <h2>代理访问白名单</h2>\n"
        "        <div class=\"info-box\">\n"
        "            <p>当前白名单状态：%s。启动参数添加 <code>--enable-whitelist</code> 后才会拦截代理客户端。</p>\n"
        "            <p>启用后，只有白名单IP可以使用HTTP/SOCKS5代理；白名单为空时外部客户端全部拒绝。</p>\n"
        "            <p>127.0.0.1 始终允许，用于本机HTTP到SOCKS5转发。</p>\n"
        "        </div>\n"
        "        <div class=\"form-group\">\n"
        "            <label for=\"allowIp\">客户端IP:</label>\n"
        "            <input type=\"text\" id=\"allowIp\" placeholder=\"例如: 203.0.113.10\"\n"
        "                   onkeypress=\"if(event.keyCode=='Enter') addAllowIp()\">\n"
        "        </div>\n"
        "        <button onclick=\"addAllowIp()\" class=\"btn-success\">添加白名单IP</button>\n"
        "        <table>\n"
        "            <thead>\n"
        "                <tr>\n"
        "                    <th>IP地址</th>\n"
        "                    <th>操作</th>\n"
        "                </tr>\n"
        "            </thead>\n"
        "            <tbody id=\"whitelistTableBody\">\n"
        "                %s\n"
        "            </tbody>\n"
        "        </table>\n"
        "        \n"
        "        <h2>添加域名规则</h2>\n"
        "        <div class=\"form-group\">\n"
        "            <label for=\"domain\">域名模式:</label>\n"
        "            <input type=\"text\" id=\"domain\" placeholder=\"例如: google.com（自动匹配子域名和后缀）\" \n"
        "                   onkeypress=\"if(event.keyCode=='Enter') addDomain()\">\n"
        "        </div>\n"
        "        <div class=\"form-group\">\n"
        "            <label for=\"proxyType\">代理类型:</label>\n"
        "            <select id=\"proxyType\">\n"
        "                <option value=\"http\">HTTP代理 (端口 %d)</option>\n"
        "                <option value=\"socks5\">SOCKS5代理 (端口 %d)</option>\n"
        "                <option value=\"auto\">自动选择 (根据PAC文件)</option>\n"
        "            </select>\n"
        "        </div>\n"
        "        <button onclick=\"addDomain()\" class=\"btn-success\">添加规则</button>\n"
        "        <div id=\"message\" class=\"message\"></div>\n"
        "        \n"
        "        <h2>域名规则列表</h2>\n"
        "        <table>\n"
        "            <thead>\n"
        "                <tr>\n"
        "                    <th>域名模式</th>\n"
        "                    <th>代理类型</th>\n"
        "                    <th>操作</th>\n"
        "                </tr>\n"
        "            </thead>\n"
        "            <tbody id=\"domainTableBody\">\n"
        "                %s\n"
        "            </tbody>\n"
        "        </table>\n"
        "        \n"
        "        <div style=\"margin-top: 30px; text-align: center; color: #666; font-size: 14px;\">\n"
        "            <p>Powered by xproxy | 规则自动保存到配置文件: %s</p>\n"
        "        </div>\n"
        "    </div>\n"
        "    \n"
        "    <script>\n"
        "        function showMessage(text, isError) {\n"
        "            var msg = document.getElementById('message');\n"
        "            msg.innerHTML = text;\n"
        "            msg.className = isError ? 'message error' : 'message success';\n"
        "            setTimeout(function() { msg.innerHTML = ''; msg.className = 'message'; }, 3000);\n"
        "        }\n"
        "        \n"
        "        function refreshDomainList() {\n"
        "            fetch('/admin/api/domains')\n"
        "                .then(function(response) { return response.json(); })\n"
        "                .then(function(data) {\n"
        "                    if (data.success) {\n"
        "                        // 更新域名计数\n"
        "                        document.getElementById('domainCount').textContent = data.count;\n"
        "                        \n"
        "                        // 更新表格内容\n"
        "                        var tbody = document.getElementById('domainTableBody');\n"
        "                        var rows = '';\n"
        "                        data.domains.forEach(function(domain) {\n"
        "                            rows += '<tr>' +\n"
        "                                '<td><code>' + domain.pattern + '</code></td>' +\n"
        "                                '<td>' + domain.proxy_type + '</td>' +\n"
        "                                '<td>' +\n"
        "                                '    <button onclick=\"removeDomain(\\'' + domain.pattern.replace(/'/g, \"\\\\'\") + '\\')\" class=\"btn-delete\">删除</button>' +\n"
        "                                '</td>' +\n"
        "                                '</tr>';\n"
        "                        });\n"
        "                        if (rows === '') {\n"
        "                            rows = '<tr><td colspan=\"3\" style=\"text-align: center;\">暂无域名规则</td></tr>';\n"
        "                        }\n"
        "                        tbody.innerHTML = rows;\n"
        "                    } else {\n"
        "                        showMessage('刷新域名列表失败: ' + (data.error || '未知错误'), true);\n"
        "                    }\n"
        "                })\n"
        "                .catch(function(error) {\n"
        "                    showMessage('刷新域名列表网络错误: ' + error, true);\n"
        "                });\n"
        "        }\n"
        "        \n"
        "        function addDomain() {\n"
        "            var domain = document.getElementById('domain').value.trim();\n"
        "            var proxyType = document.getElementById('proxyType').value;\n"
        "            \n"
        "            if (!domain) {\n"
        "                showMessage('请输入域名模式', true);\n"
        "                return;\n"
        "            }\n"
        "            \n"
        "             if (domain.indexOf('.') === -1 && domain !== '*') {\n"
        "                showMessage('域名格式不正确，应包含点号或为通配符*', true);\n"
        "                return;\n"
        "            }\n"
        "            \n"
        "            // 编码URL参数\n"
        "            var url = '/admin/api/add?domain=' + encodeURIComponent(domain) + \n"
        "                      '&type=' + encodeURIComponent(proxyType);\n"
        "            \n"
        "            fetch(url)\n"
        "                .then(function(response) { return response.json(); })\n"
        "                .then(function(data) {\n"
        "                    if (data.success) {\n"
        "                        showMessage('✓ 添加成功: ' + domain, false);\n"
        "                        document.getElementById('domain').value = '';\n"
        "                        refreshDomainList(); // 动态刷新域名列表\n"
        "                    } else {\n"
        "                        showMessage('✗ 添加失败: ' + (data.error || '未知错误'), true);\n"
        "                    }\n"
        "                })\n"
        "                .catch(function(error) {\n"
        "                    showMessage('✗ 网络错误: ' + error, true);\n"
        "                });\n"
        "        }\n"
        "        \n"
        "        function removeDomain(domain) {\n"
        "            if (!confirm('确定要删除域名规则: ' + domain + ' 吗？')) {\n"
        "                return;\n"
        "            }\n"
        "            \n"
        "            var url = '/admin/api/remove?domain=' + encodeURIComponent(domain);\n"
        "            \n"
        "            fetch(url)\n"
        "                .then(function(response) { return response.json(); })\n"
        "                .then(function(data) {\n"
        "                    if (data.success) {\n"
        "                        showMessage('✓ 删除成功: ' + domain, false);\n"
        "                        refreshDomainList(); // 动态刷新域名列表\n"
        "                    } else {\n"
        "                        showMessage('✗ 删除失败: ' + (data.error || '未知错误'), true);\n"
        "                    }\n"
        "                })\n"
        "                .catch(function(error) {\n"
        "                    showMessage('✗ 网络错误: ' + error, true);\n"
        "                });\n"
        "        }\n"
        "        \n"
        "        function refreshWhitelist() {\n"
        "            fetch('/admin/api/whitelist')\n"
        "                .then(function(response) { return response.json(); })\n"
        "                .then(function(data) {\n"
        "                    if (data.success) {\n"
        "                        var tbody = document.getElementById('whitelistTableBody');\n"
        "                        var rows = '';\n"
        "                        data.ips.forEach(function(ip) {\n"
        "                            rows += '<tr>' +\n"
        "                                '<td><code>' + ip + '</code></td>' +\n"
        "                                '<td><button onclick=\"removeAllowIp(\\'' + ip + '\\')\" class=\"btn-delete\">删除</button></td>' +\n"
        "                                '</tr>';\n"
        "                        });\n"
        "                        if (rows === '') {\n"
        "                            rows = '<tr><td colspan=\"2\" style=\"text-align: center;\">暂无白名单IP，启用后仅允许本机内部转发</td></tr>';\n"
        "                        }\n"
        "                        tbody.innerHTML = rows;\n"
        "                    } else {\n"
        "                        showMessage('刷新白名单失败: ' + (data.error || '未知错误'), true);\n"
        "                    }\n"
        "                })\n"
        "                .catch(function(error) {\n"
        "                    showMessage('刷新白名单网络错误: ' + error, true);\n"
        "                });\n"
        "        }\n"
        "        \n"
        "        function addAllowIp() {\n"
        "            var ip = document.getElementById('allowIp').value.trim();\n"
        "            if (!ip) {\n"
        "                showMessage('请输入客户端IP', true);\n"
        "                return;\n"
        "            }\n"
        "            fetch('/admin/api/allow-add?ip=' + encodeURIComponent(ip))\n"
        "                .then(function(response) { return response.json(); })\n"
        "                .then(function(data) {\n"
        "                    if (data.success) {\n"
        "                        showMessage('添加白名单成功: ' + ip, false);\n"
        "                        document.getElementById('allowIp').value = '';\n"
        "                        refreshWhitelist();\n"
        "                    } else {\n"
        "                        showMessage('添加白名单失败: ' + (data.error || '未知错误'), true);\n"
        "                    }\n"
        "                })\n"
        "                .catch(function(error) { showMessage('网络错误: ' + error, true); });\n"
        "        }\n"
        "        \n"
        "        function removeAllowIp(ip) {\n"
        "            if (!confirm('确定要删除白名单IP: ' + ip + ' 吗？')) return;\n"
        "            fetch('/admin/api/allow-remove?ip=' + encodeURIComponent(ip))\n"
        "                .then(function(response) { return response.json(); })\n"
        "                .then(function(data) {\n"
        "                    if (data.success) {\n"
        "                        showMessage('删除白名单成功: ' + ip, false);\n"
        "                        refreshWhitelist();\n"
        "                    } else {\n"
        "                        showMessage('删除白名单失败: ' + (data.error || '未知错误'), true);\n"
        "                    }\n"
        "                })\n"
        "                .catch(function(error) { showMessage('网络错误: ' + error, true); });\n"
        "        }\n"
        "        \n"
        "        // 按回车键添加域名\n"
        "        document.getElementById('domain').addEventListener('keypress', function(e) {\n"
        "            if (e.key === 'Enter') {\n"
        "                addDomain();\n"
        "            }\n"
        "        });\n"
        "    </script>\n"
        "</body>\n"
        "</html>",
        g_config.http_proxy_port,      // 第一个占位符：HTTP代理端口（统计框）
        g_config.socks5_proxy_port,    // 第二个占位符：SOCKS5代理端口（统计框）
        g_domain_count,                // 第三个占位符：域名规则数（统计框）← 修复这里！
        g_config.enable_proxy_whitelist ? "启用" : "禁用",
        whitelist_rows,                // 白名单IP表格
        g_config.http_proxy_port,      // 第四个占位符：HTTP代理端口（下拉框）
        g_config.socks5_proxy_port,    // 第五个占位符：SOCKS5代理端口（下拉框）
        domain_rows,                   // 域名规则表格
        g_config.config_file ? g_config.config_file : "未配置" // 配置文件路径
    );

    printf("[PAC-DEBUG] HTML generated successfully, domain_count=%d, allow_ip_count=%d\n",
           g_domain_count, allow_row_count);
    return html;
}

// 生成状态信息JSON
static const char* generate_status_json(void) {
    static char json[1024];

    // 调试输出：打印实际值
    printf("[DEBUG] generate_status_json: http_port=%d, socks5_port=%d, domain_count=%d\n",
           g_config.http_proxy_port, g_config.socks5_proxy_port, g_domain_count);

    // 合理性检查
    int http_port = g_config.http_proxy_port;
    int socks5_port = g_config.socks5_proxy_port;
    int domain_count = g_domain_count;

    if (http_port <= 0 || http_port > 65535) {
        printf("[WARN] 无效的HTTP代理端口: %d，使用默认值7890\n", http_port);
        http_port = 7890;
    }

    if (socks5_port <= 0 || socks5_port > 65535) {
        printf("[WARN] 无效的SOCKS5代理端口: %d，使用默认值1081\n", socks5_port);
        socks5_port = 1081;
    }

    if (domain_count < 0) {
        printf("[WARN] 无效的域名规则数: %d，重置为0\n", domain_count);
        domain_count = 0;
    }

    snprintf(json, sizeof(json),
        "{\"success\":true,\"status\":{\n"
        "  \"http_proxy_port\":%d,\n"
        "  \"socks5_proxy_port\":%d,\n"
        "  \"domain_count\":%d,\n"
        "  \"web_admin_enabled\":%s,\n"
        "  \"proxy_whitelist_enabled\":%s,\n"
        "  \"proxy_whitelist_count\":%d,\n"
        "  \"config_file\":\"%s\",\n"
        "  \"initialized\":%s\n"
        "}}",
        http_port,
        socks5_port,
        domain_count,
        g_config.enable_web_admin ? "true" : "false",
        g_config.enable_proxy_whitelist ? "true" : "false",
        g_allow_ip_count,
        g_config.config_file ? g_config.config_file : "",
        g_initialized ? "true" : "false");

    return json;
}

// 生成域名列表JSON
static const char* generate_domains_json(void) {
    static char json[8192];
    int pos = 0;
    int remaining = sizeof(json);

    // 初始化JSON对象
    int written = snprintf(json + pos, remaining, "{\"success\":true,\"domains\":[");
    if (written < 0 || written >= remaining) {
        // 缓冲区不足，返回错误JSON（使用静态错误消息）
        static const char* error_json = "{\"success\":false,\"error\":\"缓冲区不足\"}";
        return error_json;
    }
    pos += written;
    remaining -= written;

    DomainRule* current = g_domain_list;
    int first = 1;
    while (current && remaining > 100) { // 保留100字节用于结束部分
        if (!first) {
            written = snprintf(json + pos, remaining, ",");
            if (written < 0 || written >= remaining) break;
            pos += written;
            remaining -= written;
        }
        first = 0;

        const char* proxy_type_str = proxy_type_to_str(current->proxy_type);
        written = snprintf(json + pos, remaining,
            "{\"pattern\":\"%s\",\"proxy_type\":\"%s\"}",
            current->pattern, proxy_type_str);
        if (written < 0 || written >= remaining) break;
        pos += written;
        remaining -= written;

        current = current->next;
    }

    // 结束JSON
    written = snprintf(json + pos, remaining, "],\"count\":%d}", g_domain_count);
    if (written < 0 || written >= remaining) {
        // 即使截断，也确保字符串以空字符结尾
        json[sizeof(json) - 1] = '\0';
    } else {
        pos += written; // 不需要使用pos，但保持一致性
    }

    return json;
}

static const char* generate_whitelist_json(void) {
    static char json[4096];
    int pos = 0;
    int remaining = sizeof(json);

    int written = snprintf(json + pos, remaining,
        "{\"success\":true,\"enabled\":%s,\"ips\":[",
        g_config.enable_proxy_whitelist ? "true" : "false");
    if (written < 0 || written >= remaining)
        return "{\"success\":false,\"error\":\"缓冲区不足\"}";
    pos += written;
    remaining -= written;

    AllowIpRule* current = g_allow_ip_list;
    int first = 1;
    while (current && remaining > 80) {
        written = snprintf(json + pos, remaining, "%s\"%s\"",
                           first ? "" : ",", current->ip);
        if (written < 0 || written >= remaining) break;
        pos += written;
        remaining -= written;
        first = 0;
        current = current->next;
    }

    snprintf(json + pos, remaining, "],\"count\":%d}", g_allow_ip_count);
    json[sizeof(json) - 1] = '\0';
    return json;
}

// ===================== 提取URL查询字符串 =====================
static const char* extract_query_string(const char* req_buf, int req_len) {
    static char query_buf[512];

    // 查找请求行结束位置
    const char* line_end = strchr(req_buf, '\r');
    if (!line_end) line_end = strchr(req_buf, '\n');
    if (!line_end) return NULL;

    // 查找问号
    const char* question_mark = strchr(req_buf, '?');
    if (!question_mark || question_mark > line_end) {
        return NULL; // 没有查询参数
    }

    // 提取查询字符串（问号后到行尾）
    const char* query_start = question_mark + 1;
    int query_len = line_end - query_start;

    if (query_len <= 0 || query_len >= sizeof(query_buf)) {
        return NULL;
    }

    strncpy(query_buf, query_start, query_len);
    query_buf[query_len] = '\0';

    return query_buf;
}

// ===================== 处理管理请求 =====================
static int handle_admin_request(SOCKET_T client_sock, const char* req_buf, int req_len, int admin_type) {
    // 检查是否启用Web管理
    if (!g_config.enable_web_admin) {
        send_error_response(client_sock, 403, "Web管理界面已禁用");
        return -1;
    }
    if (!admin_auth_ok(req_buf, req_len)) {
        send_auth_required_response(client_sock);
        return 1;
    }

    const char* query_str = extract_query_string(req_buf, req_len);
    printf("Handling admin request:%s...\n", req_buf);
    switch (admin_type) {
        case 1: // GET /admin - 管理界面
            send_html_response(client_sock, generate_admin_html());
            break;

        case 2: // GET /admin/api/domains - 获取域名列表
            send_json_response(client_sock, generate_domains_json());
            break;

        case 3: // GET /admin/api/add - 添加域名
        {
            printf("Adding domain start\n");
            if (!query_str) {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"缺少查询参数\"}");
                break;
            }

            char domain[256] = {0};
            char type_str[32] = {0};

            get_query_param(query_str, "domain", domain, sizeof(domain));
            get_query_param(query_str, "type", type_str, sizeof(type_str));
            printf("Adding domain added:%s...\n", domain);

            if (domain[0] == '\0') {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"缺少域名参数\"}");
                break;
            }

            ProxyType proxy_type = parse_proxy_type(type_str);
            int result = xpac_add_domain(domain, proxy_type);

            if (result == 0) {
                send_json_response(client_sock, "{\"success\":true,\"message\":\"域名添加成功\"}");
            } else {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"域名添加失败\"}");
            }
            break;
        }

        case 4: // GET /admin/api/remove - 删除域名
        {
            if (!query_str) {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"缺少查询参数\"}");
                break;
            }

            char domain[256] = {0};
            get_query_param(query_str, "domain", domain, sizeof(domain));

            if (domain[0] == '\0') {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"缺少域名参数\"}");
                break;
            }

            int result = xpac_remove_domain(domain);

            if (result == 0) {
                send_json_response(client_sock, "{\"success\":true,\"message\":\"域名删除成功\"}");
            } else {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"域名删除失败或不存在\"}");
            }
            break;
        }

        case 5: // GET /admin/api/status - 服务器状态
            send_json_response(client_sock, generate_status_json());
            break;

        case 6: // GET /admin/api/whitelist - 获取白名单
            send_json_response(client_sock, generate_whitelist_json());
            break;

        case 7: // GET /admin/api/allow-add - 添加白名单IP
        {
            if (!query_str) {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"缺少查询参数\"}");
                break;
            }

            char ip[64] = {0};
            get_query_param(query_str, "ip", ip, sizeof(ip));
            if (ip[0] == '\0') {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"缺少IP参数\"}");
                break;
            }

            int result = xpac_add_allow_ip(ip);
            if (result == 0) {
                send_json_response(client_sock, "{\"success\":true,\"message\":\"白名单IP添加成功\"}");
            } else {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"白名单IP添加失败\"}");
            }
            break;
        }

        case 8: // GET /admin/api/allow-remove - 删除白名单IP
        {
            if (!query_str) {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"缺少查询参数\"}");
                break;
            }

            char ip[64] = {0};
            get_query_param(query_str, "ip", ip, sizeof(ip));
            if (ip[0] == '\0') {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"缺少IP参数\"}");
                break;
            }

            int result = xpac_remove_allow_ip(ip);
            if (result == 0) {
                send_json_response(client_sock, "{\"success\":true,\"message\":\"白名单IP删除成功\"}");
            } else {
                send_json_response(client_sock, "{\"success\":false,\"error\":\"白名单IP删除失败或不存在\"}");
            }
            break;
        }

        default:
            send_error_response(client_sock, 404, "API端点不存在");
            return -1;
    }

    printf("[PAC] 处理管理请求完成 (类型: %d)\n", admin_type);
    return 1;
}

// ===================== 主处理函数 =====================
int xpac_handle_request(SOCKET_T client_sock, const char* req_buf, int req_len) {
    if (!g_initialized) {
        printf("[PAC] 警告：PAC服务器未初始化，使用默认配置\n");
        xpac_init(NULL);
    }

    // 检查是否为PAC请求
    int pac_type = is_pac_request(req_buf, req_len);
    if (pac_type > 0) {
        printf("[PAC] 检测到PAC文件请求 (类型: %d)\n", pac_type);

        // 生成动态PAC内容
        char* pac_content = xpac_generate_pac_content(pac_type);
        if (!pac_content) {
            send_error_response(client_sock, 500, "内部错误：无法生成PAC内容");
            return -1;
        }

        send_pac_response(client_sock, pac_content);
        free(pac_content);

        printf("[PAC] 已发送PAC文件响应\n");
        return 1;
    }

    // 检查是否为管理请求
    int admin_type = is_admin_request(req_buf, req_len);
    if (admin_type > 0) {
        printf("[PAC] 检测到管理请求 (类型: %d)\n", admin_type);
        return handle_admin_request(client_sock, req_buf, req_len, admin_type);
    } else {
        printf("[PAC] 未检测到pac请求\n");
    }

    // 非法请求
    send_json_response(client_sock, "{\"success\":false,\"error\":\"[PAC] 未检测到合法请求\"}");
    return 0;
}
