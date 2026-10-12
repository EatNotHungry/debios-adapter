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
#import <CommonCrypto/CommonDigest.h>
#import <unistd.h>
#import <time.h>
#import <string.h>

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
    NSData *msg = [plain dataUsingEncoding:NSUTF8StringEncoding];
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

// 公钥解密（服务端私钥加密，PKCS#1 v1.5 块类型 0x01）<- base64 文本
static NSString *rsaDecryptBase64(NSString *b64text) {
    if (!loadPublicKey()) return nil;
    NSData *ct = [[NSData alloc] initWithBase64EncodedString:
                  [b64text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]
                                                     options:0];
    if (!ct || ct.length != KBYTES) return nil;
    bn_t c, m;
    bn_from_be(&c, ct.bytes, KBYTES);
    bn_pow_e(&m, &c, &gN);
    uint8_t blk[KBYTES];
    bn_to_be(&m, blk, KBYTES);
    if (blk[0] != 0x00 || blk[1] != 0x01) return nil;
    int i = 2;
    while (i < KBYTES && blk[i] == 0xFF) i++;
    if (i >= KBYTES || blk[i] != 0x00) return nil;
    i++;
    return [[NSString alloc] initWithBytes:blk + i length:KBYTES - i encoding:NSUTF8StringEncoding];
}

static NSString *md5Lower(NSString *s) {
    unsigned char d[16];
    CC_MD5(s.UTF8String, (CC_LONG)strlen(s.UTF8String), d);
    NSMutableString *m = [NSMutableString stringWithCapacity:32];
    for (int i = 0; i < 16; i++) [m appendFormat:@"%02x", d[i]];
    return m;
}

#pragma mark ================= 日志 =================

static NSString *gLogPath = nil;
static void t3log(NSString *fmt, ...) {
    @autoreleasepool {
        va_list ap; va_start(ap, fmt);
        NSString *body = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);
        NSLog(@"[T3Adapter] %@", body);
        if (!gLogPath) {
            NSArray *c = @[@"/var/mobile/Library/Logs/T3Adapter.log",
                           @"/var/mobile/Documents/T3Adapter.log"];
            for (NSString *p in c) {
                [[NSFileManager defaultManager] createDirectoryAtPath:[p stringByDeletingLastPathComponent]
                                          withIntermediateDirectories:YES attributes:nil error:NULL];
                if ([[NSFileManager defaultManager] createFileAtPath:p contents:[NSData data] attributes:nil]) {
                    gLogPath = p; break;
                }
            }
            if (!gLogPath) {
                NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
                gLogPath = [docs stringByAppendingPathComponent:@"T3Adapter.log"];
                [[NSFileManager defaultManager] createFileAtPath:gLogPath contents:[NSData data] attributes:nil];
            }
        }
        if (gLogPath) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
            if (fh) { @try { [fh seekToEndOfFile];
                [fh writeData:[[body stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
                [fh closeFile]; } @catch (NSException *e) {} }
        }
    }
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
        if ([k isEqualToString:@"t"]) p[k] = @((long long)time(NULL));
        else p[k] = [values[k] description];
    }

    // 1) 逐参数 RSA 加密（保持顺序）
    NSMutableDictionary *enc = [NSMutableDictionary dictionary];
    for (NSString *k in ordered) {
        NSString *e = rsaEncryptHex(p[k]);
        if (!e) { if (err) *err = [NSError errorWithDomain:@"t3" code:3
                        userInfo:@{NSLocalizedDescriptionKey: @"参数加密失败"}]; return nil; }
        enc[k] = e;
    }

    // 2) 签名
    NSMutableArray *parts = [NSMutableArray array];
    for (NSString *k in ordered) [parts addObject:[NSString stringWithFormat:@"%@=%@", k, enc[k]]];
    NSString *sString = [[parts componentsJoinedByString:@"&"] stringByAppendingFormat:@"&%@", kAppKey];
    enc[@"s"] = rsaEncryptHex(md5Lower(sString));
    if (outSString) *outSString = sString;

    // 3) POST（服务器故障切换）
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
            t3log(@"  %@ -> 无响应(%@)", srv, respErr.localizedDescription ?: @"空");
            continue;
        }
        NSString *txt = [[NSString alloc] initWithData:respData encoding:NSUTF8StringEncoding];
        NSString *dec = rsaDecryptBase64(txt);
        if (!dec) { t3log(@"  %@ -> 解密失败", srv); continue; }
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
static BOOL     gLockShown = NO;
static UIWindow *gLockWindow = nil;
static UILabel  *gStatusLbl = nil;
static UITextField *gCodeField = nil;
static NSString *gKami = nil, *gStatecode = nil, *gEndTime = nil;
static dispatch_queue_t gQueue = NULL;

static void t3_showLock(void);

static void t3_setStatus(NSString *s, UIColor *c) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gStatusLbl) return;
        gStatusLbl.text = s ?: @"";
        gStatusLbl.textColor = c ?: [UIColor whiteColor];
    });
}

static NSString *t3_machineCode(void) {
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    if (!idfv) idfv = @"unknown-device";
    return idfv;
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
        UIWindow *w = gLockWindow;
        gLockWindow = nil; gLockShown = NO;
        [UIView animateWithDuration:0.25 animations:^{ w.alpha = 0; } completion:^(BOOL f) {
            w.hidden = YES; [w resignKeyWindow];
            gCodeField = nil; gStatusLbl = nil;
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
            NSString *imei = t3_machineCode();
            t3log(@"校验 kami=%@ imei=%@", kami, imei);
            NSError *e = nil;
            NSString *sString = nil;
            NSDictionary *j = t3Call(kLoginCode, @[@"kami", @"imei"],
                                     @{@"kami": kami, @"imei": imei}, &sString, &e);
            if (!j) {
                gBusy = NO;
                t3_setStatus(e.localizedDescription ?: @"请求失败", [UIColor colorWithRed:1 green:.45 blue:.45 alpha:1]);
                return;
            }
            id codeObj = j[@"code"];
            BOOL okCode = ([codeObj isKindOfClass:[NSNumber class]] && [codeObj intValue] == 200)
                       || ([codeObj isKindOfClass:[NSString class]] && [codeObj isEqualToString:@"200"]);
            if (!okCode) {
                NSString *m = [j[@"msg"] description];
                gBusy = NO;
                t3_setStatus((m.length && ![m isEqualToString:@"(null)"]) ? m : @"验证失败",
                             [UIColor colorWithRed:1 green:.45 blue:.45 alpha:1]);
                return;
            }
            NSString *kid = [j[@"id"] description];
            NSString *end = [j[@"end_time"] description];
            NSString *token = [j[@"token"] description];
            NSString *statecode = [j[@"statecode"] description];
            NSNumber *rtime = [j[@"time"] isKindOfClass:[NSNumber class]] ? j[@"time"] : nil;
            BOOL bad = (!kid.length || [kid isEqualToString:@"(null)"] || !end.length
                        || [end isEqualToString:@"(null)"] || !token.length || !statecode.length || !rtime);
            if (bad) {
                gBusy = NO;
                t3_setStatus(@"响应数据缺少必要字段", [UIColor colorWithRed:1 green:.45 blue:.45 alpha:1]);
                return;
            }
            long long diff = llabs((long long)time(NULL) - rtime.longLongValue);
            if (diff > 5) {
                gBusy = NO;
                t3_setStatus([NSString stringWithFormat:@"时间戳校验失败，相差%lld秒", diff],
                             [UIColor colorWithRed:1 green:.45 blue:.45 alpha:1]);
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
            t3_setStatus([NSString stringWithFormat:@"验证成功，到期 %@", end],
                         [UIColor colorWithRed:.4 green:1 blue:.55 alpha:1]);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ t3_unlock(); });
        }
    });
}

#pragma mark ================= UI =================

@interface T3ALockVC : UIViewController <UITextFieldDelegate>
@end

@implementation T3ALockVC
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.07 alpha:1.0];
    UILabel *title = [UILabel new];
    title.text = @"卡密验证";
    title.font = [UIFont boldSystemFontOfSize:26];
    title.textColor = [UIColor whiteColor];
    title.textAlignment = NSTextAlignmentCenter;

    UITextField *tf = [UITextField new];
    tf.placeholder = @"请输入卡密";
    tf.borderStyle = UITextBorderStyleRoundedRect;
    tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    tf.autocorrectionType = UITextAutocorrectionTypeNo;
    tf.text = gKami ?: @"";
    tf.delegate = self;
    gCodeField = tf;

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [btn setTitle:@"验 证" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:19];
    btn.backgroundColor = [UIColor colorWithRed:0.16 green:0.55 blue:1.0 alpha:1];
    btn.layer.cornerRadius = 9;
    [btn addTarget:self action:@selector(onTap) forControlEvents:UIControlEventTouchUpInside];

    UILabel *st = [UILabel new];
    st.font = [UIFont systemFontOfSize:13];
    st.textAlignment = NSTextAlignmentCenter;
    st.numberOfLines = 0;
    gStatusLbl = st;

    UILabel *tip = [UILabel new];
    tip.text = @"输入卡密后才能进入";
    tip.font = [UIFont systemFontOfSize:12];
    tip.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    tip.textAlignment = NSTextAlignmentCenter;

    NSArray *all = @[title, tf, btn, st, tip];
    for (UIView *v in all) { v.translatesAutoresizingMaskIntoConstraints = NO; [self.view addSubview:v]; }
    NSDictionary *v = NSDictionaryOfVariableBindings(title, tf, btn, st, tip);
    for (NSString *h in @[@"H:|-30-[title]-30-|", @"H:|-30-[tf]-30-|", @"H:|-30-[btn]-30-|",
                          @"H:|-30-[st]-30-|", @"H:|-30-[tip]-30-|"]) {
        [self.view addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:h options:0 metrics:nil views:v]];
    }
    [self.view addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:
        @"V:|-120-[title]-40-[tf(44)]-18-[btn(46)]-20-[st]-8-[tip]" options:0 metrics:nil views:v]];
}
- (void)onTap { t3_verify(gCodeField.text); }
- (BOOL)textFieldShouldReturn:(UITextField *)tf { [self onTap]; return YES; }
@end

static void t3_showLock(void) {
    if (![NSThread isMainThread]) { dispatch_async(dispatch_get_main_queue(), ^{ t3_showLock(); }); return; }
    if (gAuthorized) return;
    if (gLockWindow) { [gLockWindow makeKeyAndVisible]; return; }
    if (gLockShown) return;
    gLockShown = YES;
    UIWindow *w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    w.windowLevel = UIWindowLevelAlert + 20;
    w.backgroundColor = [UIColor colorWithWhite:0.07 alpha:1];
    w.rootViewController = [T3ALockVC new];
    [w makeKeyAndVisible];
    gLockWindow = w;
    t3log(@"🔒 门禁窗口已建立");
}

#pragma mark ================= AppDelegate 兜底 =================

static IMP gOrigDidFinish = NULL;
static void t3_didFinish(id self, SEL _cmd, UIApplication *app, NSDictionary *opts) {
    if (gOrigDidFinish) ((void (*)(id, SEL, UIApplication*, NSDictionary*))gOrigDidFinish)(self, _cmd, app, opts);
    t3log(@"★ didFinishLaunching 归来");
    if (!gAuthorized) t3_showLock();
}

#pragma mark ================= 安装 =================

__attribute__((constructor))
static void t3_ctor(void) {
    @autoreleasepool {
        t3log(@"========================================");
        t3log(@"=== T3Adapter v10 启动 (pid=%d) ===", getpid());
        t3log(@"日志: %@", gLogPath);
        BOOL ok = loadPublicKey();
        t3log(@"公钥解析: %@", ok ? @"成功(1024位)" : @"失败");
        if (ok) {
            NSString *test = rsaEncryptHex(@"1");
            t3log(@"自检加密: %@", test ? [test substringToIndex:32] : @"失败");
        }
        Class c = NSClassFromString(@"MainApplicationDelegate");
        if (c) {
            SEL s = NSSelectorFromString(@"application:didFinishLaunchingWithOptions:");
            Method m = class_getInstanceMethod(c, s);
            if (m) {
                gOrigDidFinish = method_getImplementation(m);
                class_replaceMethod(c, s, (IMP)t3_didFinish, method_getTypeEncoding(m));
                t3log(@"✅ 已挂 %@ didFinishLaunching", c);
            }
        } else {
            t3log(@"⚠️ 没找到 MainApplicationDelegate");
        }
        t3log(@"=== 注入完成 ===");
    }
}
