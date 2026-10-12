// =====================================================================
//  T3Adapter.m   v4 —— 强制卡密门禁 + 文件日志（真机自证版）
//
//  v3 -> v4 的关键修复：
//    ★ 绝不在 constructor 里碰 UIKit / 建 UIWindow
//      （v3 在 dyld 初始化阶段就 alloc UIWindow + makeKeyAndVisible，
//        那时 UIApplication 还没起来，是 iOS 上典型的启动闪退点）
//    ★ 窗口改到 AppDelegate didFinishLaunching 之后建
//    ★ 日志同时写文件，真机可用 Filza 直接读，不用 idevicesyslog
//    ★ 增加启动阶段标记（stage），崩溃时能看出卡在哪一步
//
//  日志文件：/var/mobile/Library/Logs/T3Adapter.log
//            （沙盒环境退化到 Documents/T3Adapter.log）
// =====================================================================

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <unistd.h>
#import "T3Verify.h"

#pragma mark ================= 配置 =================

static NSString *const kT3CardKeyStore  = @"t3_36891_kami";
static NSString *const kT3LoginCode     = @"A35160C5F5F484D7";
static NSString *const kT3NoticeCode    = @"7BD42007B52A0572";
static NSString *const kT3VersionCode   = @"C06EB382F54BAB77";
static NSString *const kT3HeartbeatCode = @"E5BCC2D6509A9A90";
static NSString *const kT3AppKey        = @"6cc04fdfdb869d955905049053e4464c";
static NSString *const kT3Base64Charset = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static NSString *const kT3PublicKeyPEM  =
    @"-----BEGIN PUBLIC KEY-----\n"
     "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5AbsPP1TTdt222VSerZlB5Ied\n"
     "+ZfgoSfgCIv4U8FhE2JKU10Eo0Ox0v4W4q64eUe/4kIHZo/S3VuZKkXmOgsaNiD5\n"
     "KAW44dm0Dgs0DDVUQitbAsmw3aL/hrbsqmBbkjXFEzeoDDjKQ42SMZ81FLakri+o\n"
     "h+BCgFUqAq3Eh58tpwIDAQAB\n"
     "-----END PUBLIC KEY-----";

#pragma mark ================= 状态 =================

static T3Verify    *gVerify     = nil;
static NSString    *gKami       = nil;
static NSString    *gStatecode  = nil;
static NSString    *gEndTime    = nil;
static BOOL         gAuthorized = NO;
static BOOL         gBusy       = NO;
static BOOL         gLockShown  = NO;
static UIWindow    *gLockWindow = nil;
static UILabel     *gStatusLbl  = nil;
static UITextField *gCodeField  = nil;
static dispatch_queue_t gQueue  = NULL;
static IMP          gOrigDidFinishLaunching = NULL;
static IMP          gOrigRootAppear        = NULL;
static NSString    *gLogPath    = nil;

static void t3a_showLock(void);
static void t3a_startVerify(NSString *kami);
static void t3a_rootAppear(id self, SEL _cmd, BOOL animated);

#pragma mark ================= 日志（NSLog + 文件） =================

static void t3a_logInit(void) {
    if (gLogPath) return;
    NSArray *cands = @[
        @"/var/mobile/Library/Logs/T3Adapter.log",       // 越狱后可读
        @"/var/mobile/Documents/T3Adapter.log",
    ];
    for (NSString *p in cands) {
        NSString *dir = [p stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                 withIntermediateDirectories:YES attributes:nil error:NULL];
        if (![[NSFileManager defaultManager] fileExistsAtPath:p]) {
            if ([[NSFileManager defaultManager] createFileAtPath:p contents:[NSData data] attributes:nil]) {
                gLogPath = p; break;
            }
        } else { gLogPath = p; break; }
    }
    if (!gLogPath) {                                  // 沙盒兜底
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gLogPath = [docs stringByAppendingPathComponent:@"T3Adapter.log"];
        [[NSFileManager defaultManager] createFileAtPath:gLogPath contents:[NSData data] attributes:nil];
    }
}

static void t3a_log(NSString *fmt, ...) {
    @autoreleasepool {
        va_list ap; va_start(ap, fmt);
        NSString *body = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);

        NSDateFormatter *f = [NSDateFormatter new];
        f.dateFormat = @"HH:mm:ss.SSS";
        NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [f stringFromDate:[NSDate date]], body];

        NSLog(@"[T3Adapter] %@", body);               // 走 syslog

        if (!gLogPath) t3a_logInit();
        if (gLogPath) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
            if (fh) {
                @try { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
                @catch (NSException *e) { }
            }
        }
    }
}

#pragma mark ================= 工具 =================

static NSString *t3a_machineCode(void) {
    Class c = NSClassFromString(@"T3Verify");
    SEL s = NSSelectorFromString(@"getMachineCode");
    if (c && [c respondsToSelector:s]) {
        id (*fn)(id, SEL) = (id (*)(id, SEL))(void *)objc_msgSend;
        id mc = fn(c, s);
        if ([mc isKindOfClass:[NSString class]] && [mc length]) return mc;
    }
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"unknown";
}

static void t3a_writeState(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    if (gKami)      [ud setObject:gKami      forKey:kT3CardKeyStore];
    if (gStatecode) [ud setObject:gStatecode forKey:@"t3a_statecode"];
    if (gEndTime)   [ud setObject:gEndTime   forKey:@"t3a_endtime"];
    [ud setInteger:(NSInteger)[[NSDate date] timeIntervalSince1970] forKey:@"t3a_verified_at"];
    [ud synchronize];
}

static void t3a_readState(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    gKami      = [ud stringForKey:kT3CardKeyStore];
    gStatecode = [ud stringForKey:@"t3a_statecode"];
    gEndTime   = [ud stringForKey:@"t3a_endtime"];
}

#pragma mark ================= SDK 初始化 =================

static T3Verify *t3a_makeVerify(void) {
    if (gVerify) return gVerify;
    t3a_log(@"SDK: 开始初始化");
    Class cls = NSClassFromString(@"T3Verify");
    if (!cls) { t3a_log(@"SDK: ❌ T3Verify 类不存在（T3Gate.dylib 没加载）"); return nil; }
    t3a_log(@"SDK: 找到 T3Verify = %p", cls);

    SEL sRsa = NSSelectorFromString(@"initRsaWithLoginCode:noticeCode:versionCode:heartbeatCode:appkey:rsaPublicKey:error:");
    if ([cls instancesRespondToSelector:sRsa]) {
        id (*fn)(id, SEL, NSString*, NSString*, NSString*, NSString*, NSString*, NSString*, NSError**) =
            (id (*)(id, SEL, NSString*, NSString*, NSString*, NSString*, NSString*, NSString*, NSError**))(void *)objc_msgSend;
        NSError *err = nil;
        gVerify = fn([cls alloc], sRsa, kT3LoginCode, kT3NoticeCode, kT3VersionCode,
                     kT3HeartbeatCode, kT3AppKey, kT3PublicKeyPEM, &err);
        t3a_log(@"SDK: RSA 模式 -> %@ %@", gVerify ? @"成功" : @"失败", [err localizedDescription] ?: @"");
    } else {
        t3a_log(@"SDK: 没有 initRsa... 方法");
    }

    if (!gVerify) {
        SEL sB64 = NSSelectorFromString(@"initWithLoginCode:noticeCode:versionCode:heartbeatCode:appkey:base64Charset:");
        if ([cls instancesRespondToSelector:sB64]) {
            id (*fn)(id, SEL, NSString*, NSString*, NSString*, NSString*, NSString*, NSString*) =
                (id (*)(id, SEL, NSString*, NSString*, NSString*, NSString*, NSString*, NSString*))(void *)objc_msgSend;
            gVerify = fn([cls alloc], sB64, kT3LoginCode, kT3NoticeCode, kT3VersionCode,
                         kT3HeartbeatCode, kT3AppKey, kT3Base64Charset);
            t3a_log(@"SDK: base64 模式 -> %@", gVerify ? @"成功" : @"失败");
        }
    }
    if (!gVerify) { t3a_log(@"SDK: ❌ 两种模式都失败"); return nil; }

    SEL sChk = NSSelectorFromString(@"checkInit:");
    if ([gVerify respondsToSelector:sChk]) {
        BOOL (*fn)(id, SEL, NSError**) = (BOOL (*)(id, SEL, NSError**))(void *)objc_msgSend;
        NSError *e = nil;
        BOOL ok = fn(gVerify, sChk, &e);
        t3a_log(@"SDK: checkInit = %@ (%@)", ok ? @"YES" : @"NO", [e localizedDescription] ?: @"");
    }
    return gVerify;
}

#pragma mark ================= 门禁 UI =================

static void t3a_setStatus(NSString *s, UIColor *c) {
    if (!gStatusLbl) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        gStatusLbl.text = s ?: @"";
        gStatusLbl.textColor = c ?: [UIColor whiteColor];
    });
}

static void t3a_unlock(void) {
    gAuthorized = YES;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *w = gLockWindow;
        gLockWindow = nil; gLockShown = NO;
        [UIView animateWithDuration:0.25 animations:^{ w.alpha = 0; } completion:^(BOOL f) {
            w.hidden = YES; [w resignKeyWindow];
            gCodeField = nil; gStatusLbl = nil;
        }];
    });
    t3a_log(@"✅ 验证通过，解除门禁");
}

static void t3a_startVerify(NSString *kami) {
    if (gBusy) return;
    kami = [kami stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([kami length] == 0) {
        t3a_setStatus(@"请输入卡密", [UIColor colorWithRed:1 green:.45 blue:.45 alpha:1]);
        return;
    }
    gBusy = YES;
    t3a_setStatus(@"验证中...", [UIColor colorWithWhite:.85 alpha:1]);
    dispatch_async(dispatch_get_main_queue(), ^{ [gCodeField resignFirstResponder]; });

    if (gQueue == NULL) gQueue = dispatch_queue_create("com.t3a.verify", DISPATCH_QUEUE_SERIAL);
    dispatch_async(gQueue, ^{
        @autoreleasepool {
            if (!t3a_makeVerify()) {
                gBusy = NO;
                t3a_setStatus(@"验证模块初始化失败，请重试", [UIColor colorWithRed:1 green:.45 blue:.45 alpha:1]);
                return;
            }
            gKami = [kami copy];
            NSString *imei = t3a_machineCode();
            t3a_log(@"校验: kami=%@ imei=%@", kami, imei);

            T3LoginResult *r = nil;
            SEL s = NSSelectorFromString(@"loginWithKami:imei:");
            if ([gVerify respondsToSelector:s]) {
                T3LoginResult *(*fn)(id, SEL, NSString*, NSString*) =
                    (T3LoginResult *(*)(id, SEL, NSString*, NSString*))(void *)objc_msgSend;
                r = fn(gVerify, s, kami, imei);
            }
            BOOL ok = (r && [r success]);
            NSString *msg = ok ? @"验证成功" : ([[r error] length] ? [r error] : @"验证失败");

            if (ok) {
                if ([r statecode]) gStatecode = [r statecode];
                if ([r endTime])   gEndTime   = [r endTime];
                t3a_writeState();
            }
            t3a_log(@"结果: ok=%d msg=%@ end=%@ statecode=%@", ok, msg, [r endTime], [r statecode]);

            gBusy = NO;
            if (ok) {
                t3a_setStatus([NSString stringWithFormat:@"验证成功，到期 %@", gEndTime ?: @"-"],
                              [UIColor colorWithRed:.4 green:1 blue:.55 alpha:1]);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ t3a_unlock(); });
            } else {
                t3a_setStatus(msg, [UIColor colorWithRed:1 green:.45 blue:.45 alpha:1]);
            }
        }
    });
}

@interface T3ALockVC : UIViewController <UITextFieldDelegate>
@end

@implementation T3ALockVC

- (void)viewDidLoad {
    [super viewDidLoad];
    t3a_log(@"UI: T3ALockVC viewDidLoad");
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
    [btn addTarget:self action:@selector(t3a_onTap) forControlEvents:UIControlEventTouchUpInside];

    UILabel *st = [UILabel new];
    st.font = [UIFont systemFontOfSize:14];
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
    for (NSString *h in @[@"H:|-30-[title]-30-|", @"H:|-30-[tf]-30-|",
                          @"H:|-30-[btn]-30-|", @"H:|-30-[st]-30-|", @"H:|-30-[tip]-30-|"]) {
        [self.view addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:h options:0 metrics:nil views:v]];
    }
    [self.view addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:
        @"V:|-120-[title]-40-[tf(44)]-18-[btn(46)]-20-[st]-8-[tip]" options:0 metrics:nil views:v]];
}

- (void)t3a_onTap { t3a_startVerify(gCodeField.text); }
- (BOOL)textFieldShouldReturn:(UITextField *)tf { [self t3a_onTap]; return YES; }
@end

static void t3a_showLock(void) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ t3a_showLock(); });
        return;
    }
    if (gAuthorized) { t3a_log(@"UI: 已授权，不建窗口"); return; }
    if (gLockWindow) { [gLockWindow makeKeyAndVisible]; return; }
    if (gLockShown)  { t3a_log(@"UI: 已经建过窗口，跳过"); return; }
    gLockShown = YES;

    t3a_log(@"UI: 准备建门禁窗口（当前 app 状态=%ld）", (long)[UIApplication sharedApplication].applicationState);

    UIWindow *w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    w.windowLevel = UIWindowLevelAlert + 20;
    w.backgroundColor = [UIColor colorWithWhite:0.07 alpha:1];
    w.rootViewController = [T3ALockVC new];
    [w makeKeyAndVisible];
    gLockWindow = w;
    t3a_log(@"UI: 🔒 门禁窗口已建立");
}

#pragma mark ================= 心跳 =================

static void t3a_startHeartbeat(void) {
    static dispatch_source_t timer = NULL;
    if (timer) return;
    if (gQueue == NULL) gQueue = dispatch_queue_create("com.t3a.verify", DISPATCH_QUEUE_SERIAL);
    timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, gQueue);
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 300ull * NSEC_PER_SEC),
                              300ull * NSEC_PER_SEC, 30ull * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        @autoreleasepool {
            if (!gVerify || !gKami || !gAuthorized) return;
            SEL s = NSSelectorFromString(@"heartbeatWithKami:statecode:");
            T3LoginResult *r = nil;
            if ([gVerify respondsToSelector:s]) {
                T3LoginResult *(*fn)(id, SEL, NSString*, NSString*) =
                    (T3LoginResult *(*)(id, SEL, NSString*, NSString*))(void *)objc_msgSend;
                r = fn(gVerify, s, gKami, gStatecode ?: @"");
            }
            if (r && [r success]) {
                if ([r statecode]) gStatecode = [r statecode];
                if ([r endTime])   gEndTime   = [r endTime];
                t3a_writeState();
                t3a_log(@"心跳: 正常，到期 %@", gEndTime);
            } else {
                t3a_log(@"心跳: 失败 %@", [r error] ?: @"?");
            }
        }
    });
    dispatch_resume(timer);
    t3a_log(@"心跳: 定时器已启动");
}

#pragma mark ================= AppDelegate（建窗口的唯一时机） =================

static void t3a_appDidFinishLaunching(id self, SEL _cmd, UIApplication *app, NSDictionary *opts) {
    t3a_log(@"★ didFinishLaunching 进入 (orig=%p)", gOrigDidFinishLaunching);
    if (gOrigDidFinishLaunching) {
        ((void (*)(id, SEL, UIApplication*, NSDictionary*))gOrigDidFinishLaunching)(self, _cmd, app, opts);
        t3a_log(@"★ didFinishLaunching 原实现已执行");
    }
    if (!gAuthorized) t3a_showLock();
}

static BOOL t3a_installDelegateHook(void) {
    Class c = NSClassFromString(@"MainApplicationDelegate");
    if (!c) {
        NSString *n = [NSBundle mainBundle].infoDictionary[@"NSPrincipalClass"];
        if (n) c = NSClassFromString(n);
    }
    if (!c) {
        id d = [UIApplication sharedApplication].delegate;
        if (d) c = object_getClass(d);
    }
    if (!c) { t3a_log(@"AppDelegate: ⚠️ 找不到，兜底失败"); return NO; }

    SEL s = NSSelectorFromString(@"application:didFinishLaunchingWithOptions:");
    Method m = class_getInstanceMethod(c, s);
    if (!m) { t3a_log(@"AppDelegate: ⚠️ %@ 没有 didFinishLaunching", c); return NO; }
    gOrigDidFinishLaunching = method_getImplementation(m);
    class_replaceMethod(c, s, (IMP)t3a_appDidFinishLaunching, method_getTypeEncoding(m));
    t3a_log(@"AppDelegate: ✅ 已挂 %@ (orig=%p)", c, gOrigDidFinishLaunching);
    return YES;
}

#pragma mark ================= 兜底：根控制器出现时补窗口 =================

static void t3a_rootAppear(id self, SEL _cmd, BOOL animated) {
    if (gOrigRootAppear) {
        ((void (*)(id, SEL, BOOL))gOrigRootAppear)(self, _cmd, animated);
    }
    t3a_log(@"兜底: RootViewController viewDidAppear 触发");
    if (!gAuthorized) t3a_showLock();
}

static void t3a_installRootVCFallback(void) {
    Class rc = NSClassFromString(@"RootViewController");
    if (!rc) { t3a_log(@"兜底: 没有 RootViewController"); return; }
    SEL s = NSSelectorFromString(@"viewDidAppear:");
    Method m = class_getInstanceMethod(rc, s);
    if (!m) { t3a_log(@"兜底: RootViewController 没有 viewDidAppear:"); return; }
    gOrigRootAppear = method_getImplementation(m);
    class_replaceMethod(rc, s, (IMP)t3a_rootAppear, method_getTypeEncoding(m));
    t3a_log(@"兜底: ✅ 已挂 RootViewController viewDidAppear: (orig=%p)", gOrigRootAppear);
}

#pragma mark ================= 安装 =================

static void t3a_install(void) {
    @autoreleasepool {
        t3a_logInit();
        t3a_log(@"========================================");
        t3a_log(@"=== T3Adapter v4 启动 (pid=%d) ===", getpid());
        t3a_log(@"日志文件: %@", gLogPath);

        t3a_readState();
        t3a_log(@"状态: 缓存卡密=%@  到期=%@", gKami ?: @"(无)", gEndTime ?: @"(无)");

        // ★ 只做「不碰 UI」的注入，绝不在这里建窗口
        if (!t3a_installDelegateHook()) t3a_installRootVCFallback();

        t3a_startHeartbeat();

        if (gQueue == NULL) gQueue = dispatch_queue_create("com.t3a.verify", DISPATCH_QUEUE_SERIAL);
        dispatch_async(gQueue, ^{ t3a_makeVerify(); });

        t3a_log(@"=== 注入完成（窗口等 didFinishLaunching）===");
    }
}

__attribute__((constructor))
static void t3a_ctor(void) {
    // constructor 里只做零 UI 的事
    t3a_install();
}
