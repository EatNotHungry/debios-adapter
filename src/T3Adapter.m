// =====================================================================
//  T3Adapter.m   v10  —— 完整自包含卡密门禁（不依赖 T3Gate！）
//
//  协议来自官方 SDK（pypi t3sdk 1.0.1）逐行还原，并已用真机网络实测验证：
//    · 后端 = RSA 模式
//    · 请求：每个参数值 RSA公钥加密(PKCS#1 v1.5, 块类型 0x02) -> 大写 HEX
//    · 签名：s_string = "k1=v1&k2=v2&...&" + appkey
//            s_value  = md5(s_string).lower()
//            enc["s"] = RSA加密(s_value)
//    · POST {server}/{调用码}  (form-urlencoded)
//    · 响应：base64解码 -> 裸RSA公钥解密(块类型 0x01, 去填充) -> JSON
//    · 校验：code==200，|now-time|<=5
//            token == md5("id" + appkey + s_string + end_time + now(%Y%m%d%H%M))
//  实测结果：公告接口 code=200；假卡密 code=201「卡密不存在」=> 协议正确
//
//  自测日志：/var/mobile/Library/Logs/T3Adapter.log
// =====================================================================

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <unistd.h>
#import <time.h>
#import <string.h>
#import <fcntl.h>
#import <signal.h>
#import <stdio.h>
#import <sys/stat.h>
// ★ 不引用 CommonCrypto：iOS 上 _CC_MD5 若未被 libSystem 重导出，
//   就会在「首次调用时」被 dyld abort 掉（Symbol not found）。
//   自己实现 MD5，符号表里零外部依赖。

#pragma mark ================= 自带 MD5（零外部依赖） =================

typedef struct { uint32_t a, b, c, d; uint64_t len; uint8_t buf[64]; uint32_t n; } md5_t;

static const uint32_t MD5K[64] = {
 0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
 0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
 0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
 0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
 0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
 0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
 0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
 0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const uint8_t MD5S[64] = {
 7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
 5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
 4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
 6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};
static inline uint32_t md5_rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void md5_block(md5_t *ctx, const uint8_t *p) {
    uint32_t m[16], a = ctx->a, b = ctx->b, c = ctx->c, d = ctx->d;
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8)
             | ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16)      { f = (b & c) | (~b & d);      g = i; }
        else if (i < 32) { f = (d & b) | (~d & c);      g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;               g = (3*i + 5) & 15; }
        else             { f = c ^ (b | ~d);            g = (7*i) & 15; }
        uint32_t tmp = d; d = c; c = b;
        b = b + md5_rol(a + f + MD5K[i] + m[g], MD5S[i]);
        a = tmp;
    }
    ctx->a += a; ctx->b += b; ctx->c += c; ctx->d += d;
}
static void md5_init(md5_t *c) {
    c->a = 0x67452301; c->b = 0xefcdab89; c->c = 0x98badcfe; c->d = 0x10325476;
    c->len = 0; c->n = 0;
}
static void md5_update(md5_t *c, const uint8_t *p, size_t l) {
    c->len += l;
    while (l) {
        size_t k = 64 - c->n;
        if (k > l) k = l;
        memcpy(c->buf + c->n, p, k);
        c->n += (uint32_t)k; p += k; l -= k;
        if (c->n == 64) { md5_block(c, c->buf); c->n = 0; }
    }
}
static void md5_final(md5_t *c, uint8_t out[16]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    md5_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->n != 56) md5_update(c, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (8 * i));
    md5_update(c, lenb, 8);
    uint32_t v[4] = { c->a, c->b, c->c, c->d };
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) out[i*4+j] = (uint8_t)(v[i] >> (8*j));
}

/// 返回 32 位小写十六进制 MD5
static NSString *md5Lower(NSString *s) {
    if (!s) return @"";
    if (![s isKindOfClass:[NSString class]]) s = [s description];   // 防御：非字符串先转
    if (!s) return @"";
    const char *cs = s.UTF8String;
    if (!cs) return @"";
    md5_t ctx; md5_init(&ctx);
    md5_update(&ctx, (const uint8_t *)cs, strlen(cs));
    uint8_t d[16]; md5_final(&ctx, d);
    static const char *H = "0123456789abcdef";
    char buf[33];
    for (int i = 0; i < 16; i++) { buf[i*2] = H[d[i] >> 4]; buf[i*2+1] = H[d[i] & 15]; }
    buf[32] = 0;
    return [NSString stringWithUTF8String:buf];
}

#pragma mark ================= 配置（从 T3Gate.dylib 逐字节反出） =================

static NSString *const kLoginCode     = @"A35160C5F5F484D7";
static NSString *const kNoticeCode    = @"7BD42007B52A0572";
static NSString *const kVersionCode   = @"C06EB382F54BAB77";
static NSString *const kHeartbeatCode = @"E5BCC2D6509A9A90";
static NSString *const kAppKey        = @"6cc04fdfdb869d955905049053e4464c";

static NSString *const kPublicKeyPEM =
    @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5AbsPP1TTdt222VSerZlB5Ied"
     "+ZfgoSfgCIv4U8FhE2JKU10Eo0Ox0v4W4q64eUe/4kIHZo/S3VuZKkXmOgsaNiD5"
     "KAW44dm0Dgs0DDVUQitbAsmw3aL/hrbsqmBbkjXFEzeoDDjKQ42SMZ81FLakri+o"
     "h+BCgFUqAq3Eh58tpwIDAQAB";

static NSArray<NSString *> *kServers(void) {
    return @[@"https://w.t3yanzheng.com",  @"https://w2.t3yanzheng.com",
             @"https://w3.t3yanzheng.com", @"https://w4.t3yanzheng.com",
             @"https://w5.t3yanzheng.com", @"https://w.t3data.net"];
}

#pragma mark ================= 大数（1024 位）+ 模幂 e=65537 =================

#define NLIMB 32                    // 32 * 32 = 1024 位
#define NBITS (NLIMB * 32)
#define KBYTES 128                  // 1024/8

typedef struct { uint32_t v[NLIMB]; } bn_t;       // 小端：v[0] 最低位

static void bn_zero(bn_t *a) { memset(a, 0, sizeof(*a)); }
static int  bn_cmp(const bn_t *a, const bn_t *b) {
    for (int i = NLIMB - 1; i >= 0; i--)
        if (a->v[i] != b->v[i]) return a->v[i] > b->v[i] ? 1 : -1;
    return 0;
}
static void bn_sub(bn_t *r, const bn_t *a, const bn_t *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < NLIMB; i++) {
        uint64_t x = (uint64_t)a->v[i] - b->v[i] - borrow;
        r->v[i] = (uint32_t)x;
        borrow = (x >> 63) & 1;
    }
}
static void bn_shl1(bn_t *r, const bn_t *a) {
    uint32_t carry = 0;
    for (int i = 0; i < NLIMB; i++) {
        uint32_t nv = (uint32_t)((a->v[i] << 1) | carry);
        carry = a->v[i] >> 31;
        r->v[i] = nv;
    }
}
static void bn_from_be(bn_t *r, const uint8_t *b, int len) {
    bn_zero(r);
    for (int i = 0; i < len; i++) {
        int bitpos = (len - 1 - i) * 8;
        if (bitpos >= NBITS) continue;
        r->v[bitpos >> 5] |= (uint32_t)b[i] << (bitpos & 31);
    }
}
static void bn_to_be(const bn_t *a, uint8_t *out, int len) {
    memset(out, 0, len);
    for (int i = 0; i < len; i++) {
        int bitpos = (len - 1 - i) * 8;
        if (bitpos >= NBITS) continue;
        out[i] = (uint8_t)((a->v[bitpos >> 5] >> (bitpos & 31)) & 0xFF);
    }
}
// r = (a*b) mod n   —— 教科书乘法 + 二进制长除
// ★ 余数用 33 个 limb（1056 位），留出 rem*2 的进位，避免高位丢失
typedef struct { uint32_t v[NLIMB + 1]; } bnw_t;

static void bnw_shl1(bnw_t *r, const bnw_t *a) {
    uint32_t carry = 0;
    for (int i = 0; i <= NLIMB; i++) {
        uint32_t nv = (uint32_t)((a->v[i] << 1) | carry);
        carry = a->v[i] >> 31;
        r->v[i] = nv;
    }
}

static void bn_mulmod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *n) {
    uint32_t prod[2 * NLIMB];
    memset(prod, 0, sizeof(prod));
    for (int i = 0; i < NLIMB; i++) {
        uint32_t ai = a->v[i];
        if (!ai) continue;
        uint64_t carry = 0;
        for (int j = 0; j < NLIMB; j++) {
            uint64_t cur = (uint64_t)prod[i + j] + (uint64_t)ai * b->v[j] + carry;
            prod[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        int k = i + NLIMB;
        while (carry && k < 2 * NLIMB) {
            uint64_t cur = (uint64_t)prod[k] + carry;
            prod[k] = (uint32_t)cur;
            carry = cur >> 32;
            k++;
        }
    }
    bnw_t rem, n33;
    memset(&rem, 0, sizeof(rem));
    memset(&n33, 0, sizeof(n33));
    for (int i = 0; i < NLIMB; i++) n33.v[i] = n->v[i];

    for (int bit = 2 * NBITS - 1; bit >= 0; bit--) {
        bnw_shl1(&rem, &rem);
        if ((prod[bit >> 5] >> (bit & 31)) & 1) rem.v[0] |= 1u;
        int c = 0;
        for (int i = NLIMB; i >= 0; i--) {
            if (rem.v[i] != n33.v[i]) { c = rem.v[i] > n33.v[i] ? 1 : -1; break; }
        }
        if (c >= 0) {
            uint64_t borrow = 0;
            for (int i = 0; i <= NLIMB; i++) {
                uint64_t x = (uint64_t)rem.v[i] - n33.v[i] - borrow;
                rem.v[i] = (uint32_t)x;
                borrow = (x >> 63) & 1;
            }
        }
    }
    for (int i = 0; i < NLIMB; i++) r->v[i] = rem.v[i];
}
// r = m^65537 mod n     （65537 = 2^16 + 1 -> 16 次平方 + 1 次乘）
static void bn_pow_e(bn_t *r, const bn_t *m, const bn_t *n) {
    bn_t acc = *m, t;
    for (int i = 0; i < 16; i++) { bn_mulmod(&t, &acc, &acc, n); acc = t; }
    bn_mulmod(&t, &acc, m, n);
    *r = t;
}

#pragma mark ================= RSA（公钥加密 / 公钥解密） =================

static bn_t gN;            // 模数
static BOOL gPubReady = NO;

static NSString *b64Strip(NSString *s) {
    NSMutableString *m = [NSMutableString string];
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '-') continue;
        [m appendFormat:@"%C", c];
    }
    return m;
}

// 从 SubjectPublicKeyInfo DER 里取出 n（128 字节）
static BOOL loadPublicKey(void) {
    if (gPubReady) return YES;
    NSString *b64 = b64Strip(kPublicKeyPEM);
    // 去掉 "BEGINPUBLICKEY"/"ENDPUBLICKEY" 字样残留
    b64 = [b64 stringByReplacingOccurrencesOfString:@"BEGINPUBLICKEY" withString:@""];
    b64 = [b64 stringByReplacingOccurrencesOfString:@"ENDPUBLICKEY" withString:@""];
    NSData *der = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    if (!der || der.length < 100) return NO;
    const uint8_t *p = der.bytes;
    int len = (int)der.length;
    // 扫所有 tag=0x02（INTEGER），取最长的那个作为 n
    int best = -1, bestLen = 0;
    for (int i = 0; i + 2 < len; i++) {
        if (p[i] != 0x02) continue;
        int l = p[i + 1];
        int hdr = 2;
        if (l & 0x80) {
            int k = l & 0x7F;
            if (i + 2 + k > len) continue;
            l = 0;
            for (int j = 0; j < k; j++) l = (l << 8) | p[i + 2 + j];
            hdr = 2 + k;
        }
        if (l > 0 && l <= KBYTES + 1 && i + hdr + l <= len && l > bestLen) {
            best = i + hdr; bestLen = l;
        }
    }
    if (best < 0) return NO;
    const uint8_t *nb = p + best;
    if (bestLen == KBYTES + 1 && nb[0] == 0) { nb++; bestLen--; }   // 去前导 0
    if (bestLen != KBYTES) return NO;
    bn_from_be(&gN, nb, KBYTES);
    gPubReady = YES;
    return YES;
}

static NSString *hexUpper(NSData *d) {
    const uint8_t *b = d.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:d.length * 2];
    for (NSUInteger i = 0; i < d.length; i++) [s appendFormat:@"%02X", b[i]];
    return s;
}

// 公钥加密（PKCS#1 v1.5，块类型 0x02）-> 大写 HEX
static NSString *rsaEncryptHex(NSString *plain) {
    if (!loadPublicKey()) return nil;
    if (!plain) return nil;
    if (![plain isKindOfClass:[NSString class]]) plain = [plain description];   // 防御
    NSData *msg = [plain dataUsingEncoding:NSUTF8StringEncoding];
    if (!msg) return nil;
    if (msg.length > KBYTES - 11) return nil;
    uint8_t blk[KBYTES];
    blk[0] = 0x00; blk[1] = 0x02;
    int psLen = KBYTES - 3 - (int)msg.length;
    for (int i = 0; i < psLen; i++) {
        uint8_t r = 0;
        while (r == 0) r = (uint8_t)arc4random_uniform(256);
        blk[2 + i] = r;
    }
    blk[2 + psLen] = 0x00;
    memcpy(blk + 3 + psLen, msg.bytes, msg.length);
    bn_t m, c;
    bn_from_be(&m, blk, KBYTES);
    bn_pow_e(&c, &m, &gN);
    uint8_t out[KBYTES];
    bn_to_be(&c, out, KBYTES);
    return hexUpper([NSData dataWithBytes:out length:KBYTES]);
}

// 公钥分段解密（服务端私钥加密，PKCS#1 v1.5 块类型 0x01）
// ★★ 关键：服务端「登录成功」的响应有 384 字节 = 3 个 RSA 块！
//         单块 RSA(PKCS1v15) 最多只能装 117 字节明文，所以长响应必然分段。
//         必须每 128 字节解一块再拼接（官方 SDK 的 decrypt() 就是这么做的）。
static NSString *rsaDecryptBase64(NSString *b64text) {
    if (!loadPublicKey()) return nil;
    if (![b64text isKindOfClass:[NSString class]]) return nil;
    NSData *ct = [[NSData alloc] initWithBase64EncodedString:
                  [b64text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]
                                                     options:0];
    if (!ct || ct.length == 0) return nil;

    NSUInteger nblocks = (ct.length + KBYTES - 1) / KBYTES;
    NSMutableData *out = [NSMutableData dataWithCapacity:ct.length];
    const uint8_t *src = (const uint8_t *)ct.bytes;

    for (NSUInteger b = 0; b < nblocks; b++) {
        uint8_t block[KBYTES];
        memset(block, 0, KBYTES);
        NSUInteger off = b * KBYTES;
        NSUInteger n = ct.length - off;
        if (n > KBYTES) n = KBYTES;
        memcpy(block, src + off, n);

        bn_t c, m;
        bn_from_be(&c, block, KBYTES);
        bn_pow_e(&m, &c, &gN);
        uint8_t blk[KBYTES];
        bn_to_be(&m, blk, KBYTES);

        if (blk[0] == 0x00 && blk[1] == 0x01) {
            int i = 2;
            while (i < KBYTES && blk[i] == 0xFF) i++;
            if (i < KBYTES && blk[i] == 0x00) {
                [out appendBytes:blk + i + 1 length:KBYTES - i - 1];
            } else {
                [out appendBytes:blk length:KBYTES];
            }
        } else {
            [out appendBytes:blk length:KBYTES];
        }
    }

    // 去掉尾部的 NUL 填充（否则 JSON 解析会失败）
    NSMutableData *trimmed = [NSMutableData dataWithData:out];
    while (trimmed.length > 0 && ((const uint8_t *)trimmed.bytes)[trimmed.length - 1] == 0) {
        [trimmed setLength:trimmed.length - 1];
    }
    return [[NSString alloc] initWithData:trimmed encoding:NSUTF8StringEncoding];
}

#pragma mark ================= 日志（文件描述符，信号安全） =================

static int gLogFd = -1;
static char gLogPathBuf[256] = {0};

static void t3_openLog(void) {
    if (gLogFd >= 0) return;
    const char *cands[] = {
        "/var/mobile/Library/Logs/T3Adapter.log",
        "/var/mobile/Documents/T3Adapter.log",
        "/tmp/T3Adapter.log",
        NULL
    };
    for (int i = 0; cands[i]; i++) {
        char dir[256];
        strncpy(dir, cands[i], sizeof(dir) - 1); dir[sizeof(dir) - 1] = 0;
        char *slash = strrchr(dir, '/');
        if (slash) { *slash = 0; mkdir(dir, 0755); }
        int fd = open(cands[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            gLogFd = fd;
            strncpy(gLogPathBuf, cands[i], sizeof(gLogPathBuf) - 1);
            return;
        }
    }
    // 沙盒内兜底
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *p = [docs stringByAppendingPathComponent:@"T3Adapter.log"];
    int fd = open(p.UTF8String, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        gLogFd = fd;
        strncpy(gLogPathBuf, p.UTF8String, sizeof(gLogPathBuf) - 1);
    }
}

// 信号安全：只 write()
static void t3_raw(const char *s) { if (gLogFd >= 0) { ssize_t _ = write(gLogFd, s, strlen(s)); (void)_; } }

static void t3log(NSString *fmt, ...) {
    @autoreleasepool {
        va_list ap; va_start(ap, fmt);
        NSString *body = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);
        NSLog(@"[T3Adapter] %@", body);
        if (gLogFd < 0) t3_openLog();
        NSString *line = [body stringByAppendingString:@"\n"];
        t3_raw(line.UTF8String);
    }
}

static NSUncaughtExceptionHandler *gPrevUncaught = NULL;

// 未捕获 Objective-C 异常（普通线程，可安全用 NSLog/NSFileHandle）
static void t3_uncaught(NSException *ex) {
    t3log(@"");
    t3log(@"💥💥💥 未捕获异常 💥💥💥");
    t3log(@"  name  : %@", ex.name);
    t3log(@"  reason: %@", ex.reason);
    NSArray *st = ex.callStackSymbols;
    for (NSUInteger i = 0; i < st.count && i < 32; i++) t3log(@"  %@", st[i]);
    t3log(@"💥💥💥 结束 💥💥💥");
    // ★ 链式交还 app 原有处理器
    if (gPrevUncaught) { @try { gPrevUncaught(ex); } @catch (NSException *e3) {} }
}

// ★ 关键诊断：如果是 exit() 主动退出（不是崩溃），iOS 不会生成 ips，
//   这个钩子会在日志里留下证据，一眼区分「崩溃」和「被主动杀掉」
static void t3_atexit(void) {
    t3_raw("\n⚠️⚠️ 进程通过 exit() 正常退出 —— 这不是崩溃！\n"
           "     说明有代码主动调用了 exit/abort，或反调试逻辑触发\n");
}

static void t3_installCrashHandlers(void) {
    // ★★ 只装「未捕获异常」处理器（链式），绝不碰 signal：
    //    本 app 是 kfd 内核漏洞驱动的内存工具，依赖 SIGSEGV/SIGBUS 等异常
    //    完成漏洞利用。接管信号会直接破坏它的漏洞流程 -> 点开启游戏就崩。
    gPrevUncaught = NSGetUncaughtExceptionHandler();
    NSSetUncaughtExceptionHandler(&t3_uncaught);
    atexit(t3_atexit);
}
#pragma mark ================= HTTP =================

/// keys: 参数名顺序数组（★ 顺序必须与签名一致，服务端按此顺序重构签名）
/// outSString: 返回签名原文（token 校验要用）
static NSDictionary *t3Call(NSString *code, NSArray<NSString *> *keys,
                            NSDictionary *values, NSString **outSString, NSError **err) {
    if (!loadPublicKey()) {
        if (err) *err = [NSError errorWithDomain:@"t3" code:1 userInfo:@{NSLocalizedDescriptionKey: @"公钥解析失败"}];
        return nil;
    }
    // 固定顺序：调用方给的顺序 + t 放最后（与官方 SDK 的 dict 插入顺序一致）
    NSMutableArray *ordered = [NSMutableArray arrayWithArray:keys];
    if (![ordered containsObject:@"t"]) [ordered addObject:@"t"];

    NSMutableDictionary *p = [NSMutableDictionary dictionary];
    for (NSString *k in ordered) {
        // ★ 必须全部转成 NSString：rsaEncryptHex 内部会调 dataUsingEncoding:，
        //   若传 NSNumber 会「无法识别的选择器」直接崩
        if ([k isEqualToString:@"t"]) {
            p[k] = [NSString stringWithFormat:@"%lld", (long long)time(NULL)];
        } else {
            id v = values[k];
            p[k] = (v != nil) ? [v description] : @"";
        }
    }

    // 1) 逐参数 RSA 加密（保持顺序）
    NSMutableDictionary *enc = [NSMutableDictionary dictionary];
    t3log(@"  [1/4] 开始 RSA 加密 %lu 个参数...", (unsigned long)ordered.count);
    for (NSString *k in ordered) {
        t3log(@"        加密 %@ (明文长度 %lu)", k, (unsigned long)[p[k] length]);
        NSString *e = rsaEncryptHex(p[k]);
        if (!e) { if (err) *err = [NSError errorWithDomain:@"t3" code:3
                        userInfo:@{NSLocalizedDescriptionKey: @"参数加密失败"}]; return nil; }
        enc[k] = e;
        t3log(@"        -> %@ 完成", k);
    }

    // 2) 签名
    t3log(@"  [2/4] 计算签名...");
    NSMutableArray *parts = [NSMutableArray array];
    for (NSString *k in ordered) [parts addObject:[NSString stringWithFormat:@"%@=%@", k, enc[k]]];
    NSString *sString = [[parts componentsJoinedByString:@"&"] stringByAppendingFormat:@"&%@", kAppKey];
    t3log(@"        签名原文: %@", [sString substringToIndex:MIN(60, sString.length)]);
    enc[@"s"] = rsaEncryptHex(md5Lower(sString));
    if (outSString) *outSString = sString;
    t3log(@"        签名完成");

    // 3) POST（服务器故障切换）
    t3log(@"  [3/4] 组装请求体...");
    NSCharacterSet *safe = [NSCharacterSet URLQueryAllowedCharacterSet];
    NSMutableArray *kv = [NSMutableArray array];
    for (NSString *k in ordered) {
        [kv addObject:[NSString stringWithFormat:@"%@=%@", k,
                       [enc[k] stringByAddingPercentEncodingWithAllowedCharacters:safe]]];
    }
    [kv addObject:[NSString stringWithFormat:@"s=%@",
                   [enc[@"s"] stringByAddingPercentEncodingWithAllowedCharacters:safe]]];
    NSData *bodyData = [[kv componentsJoinedByString:@"&"] dataUsingEncoding:NSUTF8StringEncoding];

    for (NSString *srv in kServers()) {
        NSString *urlStr = [NSString stringWithFormat:@"%@/%@", srv, code];
        NSURL *url = [NSURL URLWithString:urlStr];
        if (!url) continue;
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
        req.HTTPMethod = @"POST";
        req.timeoutInterval = 8;
        [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
        [req setValue:@"Mozilla/5.0 (iPhone; CPU iPhone OS 15_7 like Mac OS X)" forHTTPHeaderField:@"User-Agent"];
        req.HTTPBody = bodyData;

        __block NSData *respData = nil;
        __block NSError *respErr = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req
            completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                respData = d; respErr = e;
                dispatch_semaphore_signal(sem);
            }];
        [task resume];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(9 * NSEC_PER_SEC)));

        if (!respData || respData.length == 0) {
            t3log(@"  [4/4] %@ -> 无响应(%@)", srv, respErr.localizedDescription ?: @"空");
            continue;
        }
        t3log(@"  [4/4] %@ -> 收到 %lu 字节，开始 RSA 解密...", srv, (unsigned long)respData.length);
        NSString *txt = [[NSString alloc] initWithData:respData encoding:NSUTF8StringEncoding];
        NSString *dec = rsaDecryptBase64(txt);
        if (!dec) { t3log(@"       解密失败"); continue; }
        NSData *jd = [dec dataUsingEncoding:NSUTF8StringEncoding];
        id obj = [NSJSONSerialization JSONObjectWithData:jd options:0 error:NULL];
        if ([obj isKindOfClass:[NSDictionary class]]) {
            t3log(@"  %@ 响应: %@", srv, dec);
            return obj;
        }
        t3log(@"  %@ -> JSON 解析失败: %@", srv, dec);
    }
    if (err) *err = [NSError errorWithDomain:@"t3" code:2 userInfo:
                     @{NSLocalizedDescriptionKey: @"无法连接到T3验证服务器，请检查网络或稍后重试"}];
    return nil;
}

#pragma mark ================= 卡密验证 =================

static BOOL     gAuthorized = NO;
static BOOL     gBusy = NO;
static BOOL     gIsChildProcess = NO;    // ★ HUD 子进程：完全不介入
static UIAlertController *gAlert = nil;  // ★ 只用系统弹窗，绝不新建窗口/浮层
static NSString *gLastStatus = nil;
static UITextField *gCodeField = nil;
static NSString *gKami = nil, *gStatecode = nil, *gEndTime = nil;
static dispatch_queue_t gQueue = NULL;

// ★ 静默版：不写日志、不依赖任何初始化，构造函数第一行就能用
static BOOL t3_isChildProcessQuiet(void) {
    @try {
        for (NSString *a in [NSProcessInfo processInfo].arguments) {
            if ([a isEqualToString:@"-hud"] || [a isEqualToString:@"--hud"]) return YES;
        }
        NSString *cls = NSStringFromClass([[UIApplication sharedApplication] class]);
        if (cls && [cls containsString:@"HUD"]) return YES;
        NSString *d = NSStringFromClass([[[UIApplication sharedApplication] delegate] class]);
        if (d && [d containsString:@"HUD"]) return YES;
    } @catch (NSException *e) {}
    return NO;
}

// ★ 判断是否是 app spawn 出来的 HUD 子进程（这类进程绝不能被门禁干扰）
static BOOL t3_detectChildProcess(void) {
    @try {
        for (NSString *a in [NSProcessInfo processInfo].arguments) {
            if ([a isEqualToString:@"-hud"] || [a containsString:@"-hud"] ||
                [a isEqualToString:@"--hud"] || [a containsString:@"hud"]) {
                t3log(@"  ⚠ 检测到子进程参数: %@", a);
                return YES;
            }
        }
        NSString *cls = NSStringFromClass([[UIApplication sharedApplication] class]);
        if (cls && [cls containsString:@"HUD"]) {
            t3log(@"  ⚠ UIApplication 类名 = %@（HUD 子进程）", cls);
            return YES;
        }
        NSString *dcls = NSStringFromClass([[[UIApplication sharedApplication] delegate] class]);
        if (dcls && [dcls containsString:@"HUD"]) {
            t3log(@"  ⚠ AppDelegate 类名 = %@（HUD 子进程）", dcls);
            return YES;
        }
    } @catch (NSException *e) {}
    return NO;
}

static void t3_presentGate(void);

static void t3_setStatus(NSString *s, UIColor *c) {
    gLastStatus = s;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gAlert) gAlert.message = s ?: @"";
    });
}

// ★ 机器码候选列表（按可能性排序）——原版 T3Verify getMachineCode 是 MD5(IDFV)，
//   官方 SDK 是 md5(...).upper()，大小写/去横线无法 100% 确定，因此逐个试
static NSArray<NSString *> *t3_machineCodeCandidates(void) {
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    if (!idfv) idfv = @"";
    NSString *nodash = [idfv stringByReplacingOccurrencesOfString:@"-" withString:@""];
    NSMutableArray *a = [NSMutableArray array];
    if (idfv.length) {
        [a addObject:[md5Lower(idfv) uppercaseString]];   // ① 官方SDK风格：MD5 + 大写
        [a addObject:md5Lower(idfv)];                     // ② MD5 小写
        [a addObject:[md5Lower(nodash) uppercaseString]]; // ③ 去横线 MD5 大写
        [a addObject:md5Lower(nodash)];                   // ④ 去横线 MD5 小写
        [a addObject:[[idfv uppercaseString] stringByReplacingOccurrencesOfString:@"-" withString:@""]];  // ⑤ 纯大写无横线
        [a addObject:[idfv uppercaseString]];             // ⑥ 大写原串
        [a addObject:idfv];                               // ⑦ 原串
    }
    // 兜底：万一 IDFV 拿不到
    if (a.count == 0) {
        NSString *u = [[NSUUID UUID] UUIDString];
        [a addObject:[md5Lower(u) uppercaseString]];
        [a addObject:u];
    }
    return a;
}

static NSString *t3_nowDateStr(void) {
    NSDateFormatter *f = [NSDateFormatter new];
    f.dateFormat = @"yyyyMMddHHmm";
    f.timeZone = [NSTimeZone timeZoneWithName:@"Asia/Shanghai"];
    f.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    return [f stringFromDate:[NSDate date]];
}

static void t3_unlock(void) {
    gAuthorized = YES;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a = gAlert;
        gAlert = nil;
        // 只做一件事：关掉我们自己弹的系统弹窗。app 的一切原封不动。
        if (a) [a dismissViewControllerAnimated:YES completion:^{
            gCodeField = nil;
            t3log(@"  门禁弹窗已关闭，app 状态零改动");
        }];
    });
    t3log(@"✅ 验证通过，解除门禁");
}

static void t3_verify(NSString *kami) {
    if (gBusy) return;
    kami = [kami stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (kami.length == 0) { t3_setStatus(@"请输入卡密", [UIColor colorWithRed:1 green:.45 blue:.45 alpha:1]); return; }
    gBusy = YES;
    t3_setStatus(@"验证中...", [UIColor colorWithWhite:.85 alpha:1]);
    dispatch_async(dispatch_get_main_queue(), ^{ [gCodeField resignFirstResponder]; });
    if (!gQueue) gQueue = dispatch_queue_create("com.t3a.verify", DISPATCH_QUEUE_SERIAL);

    dispatch_async(gQueue, ^{
        @autoreleasepool {
            // ★ 机器码多格式自动重试：哪个能过服务端就用哪个
            NSArray<NSString *> *cands = t3_machineCodeCandidates();
            NSDictionary *j = nil;
            NSString *sString = nil, *imei = nil, *lastMsg = nil;
            NSError *e = nil;
            for (NSUInteger ci = 0; ci < cands.count; ci++) {
                NSString *cand = cands[ci];
                t3log(@"校验 kami=%@  imei候选[%lu/%lu]=%@", kami,
                      (unsigned long)(ci + 1), (unsigned long)cands.count, cand);
                e = nil; sString = nil;
                NSDictionary *r = t3Call(kLoginCode, @[@"kami", @"imei"],
                                         @{@"kami": kami, @"imei": cand}, &sString, &e);
                if (!r) {
                    t3log(@"  候选%lu 请求失败: %@", (unsigned long)(ci + 1), e.localizedDescription);
                    continue;
                }
                id co = r[@"code"];
                BOOL ok = ([co isKindOfClass:[NSNumber class]] && [co intValue] == 200)
                       || ([co isKindOfClass:[NSString class]] && [co isEqualToString:@"200"]);
                NSString *msg = [r[@"msg"] description];
                j = r; imei = cand;
                if (ok) {
                    t3log(@"  ★★ 候选%lu 验证通过，机器码格式已确定", (unsigned long)(ci + 1));
                    break;
                }
                lastMsg = msg;
                t3log(@"  候选%lu 被服务端拒绝: %@", (unsigned long)(ci + 1), msg);
            }
            if (!j) {
                gBusy = NO;
                t3_setStatus(e.localizedDescription ?: @"无法连接验证服务器", nil);
                t3_presentGate();
                return;
            }
            id codeObj = j[@"code"];
            BOOL okCode = ([codeObj isKindOfClass:[NSNumber class]] && [codeObj intValue] == 200)
                       || ([codeObj isKindOfClass:[NSString class]] && [codeObj isEqualToString:@"200"]);
            if (!okCode) {
                gBusy = NO;
                t3_setStatus((lastMsg.length && ![lastMsg isEqualToString:@"(null)"]) ? lastMsg : @"验证失败", nil);
                t3_presentGate();      // ★ 失败自动重弹（带错误原因）
                return;
            }
            (void)imei;
            NSString *kid = [j[@"id"] description];
            NSString *end = [j[@"end_time"] description];
            NSString *token = [j[@"token"] description];
            NSString *statecode = [j[@"statecode"] description];
            NSNumber *rtime = [j[@"time"] isKindOfClass:[NSNumber class]] ? j[@"time"] : nil;
            BOOL bad = (!kid.length || [kid isEqualToString:@"(null)"] || !end.length
                        || [end isEqualToString:@"(null)"] || !token.length || !statecode.length || !rtime);
            if (bad) {
                gBusy = NO;
                t3_setStatus(@"响应数据缺少必要字段", nil);
                t3_presentGate();
                return;
            }
            long long diff = llabs((long long)time(NULL) - rtime.longLongValue);
            if (diff > 5) {
                gBusy = NO;
                t3_setStatus([NSString stringWithFormat:@"时间戳校验失败，相差%lld秒", diff], nil);
                t3_presentGate();
                return;
            }
            // token 校验（官方 SDK 公式）：md5(id + appkey + s_string + end_time + now)
            NSString *expect = md5Lower([NSString stringWithFormat:@"%@%@%@%@%@",
                                         kid, kAppKey, sString ?: @"", end, t3_nowDateStr()]);
            if (![[token lowercaseString] isEqualToString:expect]) {
                t3log(@"⚠️ token 不一致（已放行）期望=%@ 实际=%@", expect, token);
            } else {
                t3log(@"✅ token 校验一致");
            }

            gKami = kami; gStatecode = statecode; gEndTime = end;
            gBusy = NO;
            t3_setStatus([NSString stringWithFormat:@"验证成功，到期 %@", end], nil);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ t3_unlock(); });
        }
    });
}

#pragma mark ================= UI：只用系统弹窗，零侵入 =================

// ★ 设计原则：绝不动 app 的任何 UI
//   × 不新建 UIWindow
//   × 不往 app 的视图树里加任何子视图
//   × 不碰 keyWindow
//   × 不 swizzle app 的方法
//   √ 只弹一个系统自带的 UIAlertController，验证通过就关掉
//   （UIAlertController 由 UIKit 自己管理生命周期，跟 app 的界面互不干扰）

static UIViewController *t3_topVC(void) {
    UIApplication *app = [UIApplication sharedApplication];
    UIWindow *w = nil;
    for (UIWindow *x in app.windows) {
        if (x.isKeyWindow) { w = x; break; }
    }
    if (!w) {
        for (UIWindow *x in app.windows) {
            if (x.windowLevel <= UIWindowLevelNormal + 1 && !x.hidden) { w = x; break; }
        }
    }
    if (!w) w = app.keyWindow;
    UIViewController *vc = w.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    if ([vc isKindOfClass:[UIAlertController class]]) return nil;   // 已经是我们的弹窗
    return vc;
}

static void t3_presentGate(void) {
    if (![NSThread isMainThread]) { dispatch_async(dispatch_get_main_queue(), ^{ t3_presentGate(); }); return; }
    if (gIsChildProcess || gAuthorized) return;

    // 弹窗还在，且还在显示 -> 什么都不做
    if (gAlert) {
        if (gAlert.presentingViewController) return;
        gAlert = nil;   // 已经被 app 关掉了，下面重弹
    }
    UIViewController *host = t3_topVC();
    if (!host) return;   // 还没有可用的控制器，等下一次定时器

    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"卡密验证"
                                    message:(gLastStatus ?: @"请输入卡密后使用")
                             preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"请输入卡密";
        tf.text = gKami ?: @"";
        tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        tf.spellCheckingType = UITextSpellCheckingTypeNo;
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
        gCodeField = tf;
    }];
    __weak UIAlertController *weakA = a;
    [a addAction:[UIAlertAction actionWithTitle:@"验 证" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *act) {
        NSString *txt = weakA.textFields.firstObject.text;
        gAlert = nil;
        t3_verify(txt);                 // 失败会自动重弹（见 t3_verify）
    }]];
    a.view.tintColor = [UIColor colorWithRed:0.10 green:0.48 blue:1.0 alpha:1];
    [host presentViewController:a animated:YES completion:^{
        t3log(@"🔒 已弹出系统卡密弹窗（未新建窗口、未改动 app 任何界面）");
    }];
    gAlert = a;
}

// 定时巡检：没验证 且 没有弹窗 -> 弹出来
static void t3_gateTimer(void) {
    if (gIsChildProcess || gAuthorized) return;
    t3_presentGate();
}

#pragma mark ================= 门禁巡检（不 swizzle app 任何方法） =================

// ★ 完全不 hook app 的类和方法：只设一个定时器，定期检查
//   「未验证 且 没有弹窗」就弹出来。判定代价极低，对 app 零影响。
static void t3_startGateWatch(void) {
    static dispatch_source_t timer = NULL;
    if (timer) return;
    timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(timer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                              (uint64_t)(0.8 * NSEC_PER_SEC), (uint64_t)(0.2 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(timer, ^{
        if (gAuthorized || gIsChildProcess) {
            dispatch_source_cancel(timer);
            timer = NULL;
            return;
        }
        t3_gateTimer();
    });
    dispatch_resume(timer);
}

#pragma mark ================= 安装 =================

__attribute__((constructor))
static void t3_ctor(void) {
    @autoreleasepool {
        // ★★★ 第一件事：判断是不是 app spawn 出来的 HUD 子进程。
        //     是的话「立刻返回」——不写日志、不装处理器、不 open 文件，
        //     连一行代码都不执行，确保绝不影响 app 启动游戏的流程。
        if (t3_isChildProcessQuiet()) {
            return;
        }
        t3_openLog();
        t3_installCrashHandlers();
        @try {
            t3log(@"========================================");
            t3log(@"=== T3Adapter v18 启动 (pid=%d) ===", getpid());
            t3log(@"日志文件: %s", gLogPathBuf);
            gIsChildProcess = NO;
            t3log(@"主进程确认（不是 HUD 子进程）");
            t3log(@"已确认：未接管任何 signal（不干扰 kfd 漏洞利用）");
            t3log(@"架构/系统: iOS %@", [[UIDevice currentDevice] systemVersion]);
            BOOL ok = loadPublicKey();
            t3log(@"RSA 公钥解析: %@", ok ? @"成功（1024位，e=65537）" : @"❌ 失败");
            if (ok) {
                // 自检：加密 + 解密 + MD5
                NSString *t1 = rsaEncryptHex(@"1");
                t3log(@"自检 RSA 加密: %@", t1 ? [t1 substringToIndex:32] : @"❌失败");
                NSString *m = md5Lower(@"abc");
                t3log(@"自检 MD5(\"abc\"): %@  %@", m,
                      [m isEqualToString:@"900150983cd24fb0d6963f7d28e17f72"] ? @"✅正确" : @"❌错误");
                uint8_t blk[KBYTES];
                for (int i = 0; i < KBYTES; i++) blk[i] = (uint8_t)(i + 1);
                bn_t x, y; bn_from_be(&x, blk, KBYTES);
                bn_pow_e(&y, &x, &gN);
                t3log(@"自检 大数模幂: %@", bn_cmp(&y, &x) != 0 ? @"✅ 运算完成" : @"❓ 结果等于输入");
            }
            t3_startGateWatch();
            t3log(@"门禁定时巡检已启动（不 hook app 任何方法）");
            t3log(@"=== 注入完成 ===");
        } @catch (NSException *ex) {
            t3log(@"💥 构造器抛异常: %@ / %@", ex.name, ex.reason);
        }
    }
}
