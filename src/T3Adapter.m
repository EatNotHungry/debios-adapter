// =====================================================================
//  T3Adapter.m   v3 —— 强制卡密门禁（编译安全的 objc_msgSend 写法）
//
//  行为：
//    1. 进程启动就建自己的 keyWindow 铺遮罩，未验证前 app 界面进不去
//    2. 挂住 AppDelegate 的 didFinishLaunching，防止被 app 自己的 window 盖住
//    3. 卡密走 T3Gate.dylib 里的 T3Verify → loginWithKami:imei:
//    4. 成功后撤遮罩；进主界面后每 5 分钟心跳
//
//  铁律（原 T3Gate 就是死在这几条上）：
//    * constructor 里绝不抛异常，失败只 NSLog + 按原逻辑继续
//    * 不读宿主类任何私有 ivar（原版读 _authed @偏移0x6B0 直接抛异常）
//    * 网络全在后台串行队列，绝不阻塞主线程（防 0x8badf00d watchdog）
//
//  编译兼容：所有 objc_msgSend 调用点先转 void* 再转目标函数指针，
//  避开新版 clang 的 -Wcast-function-type-mismatch 直接顶掉构建。
// =====================================================================

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import "T3Verify.h"

#pragma mark ================= 配置（从 T3Gate.dylib 实体反出，不必改） =================

static NSString *const kT3CardKeyStore  = @"t3_36891_kami";     // 卡密存盘键（与原版一致）
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

static void t3a_showLock(void);
static void t3a_startVerify(NSString *kami);

#pragma mark ================= 工具 =================

static void t3a_log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSLog(@"[T3Adapter] %@", [[NSString alloc] initWithFormat:fmt arguments:ap]);
    va_end(ap);
}

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
    Class cls = NSClassFromString(@"T3Verify");
    if (!cls) { t3a_log(@"❌ T3Verify 类不存在：T3Gate.dylib 没被加载"); return nil; }

    // ① RSA 模式（带签名，优先）
    SEL sRsa = NSSelectorFromString(@"initRsaWithLoginCode:noticeCode:versionCode:heartbeatCode:appkey:rsaPublicKey:error:");
    if ([cls instancesRespondToSelector:sRsa]) {
        id (*fn)(id, SEL, NSString*, NSString*, NSString*, NSString*, NSString*, NSString*, NSError**) =
            (id (*)(id, SEL, NSString*, NSString*, NSString*, NSString*, NSString*, NSString*, NSError**))(void *)objc_msgSend;
        NSError *err = nil;
        gVerify = fn([cls alloc], sRsa, kT3LoginCode, kT3NoticeCode, kT3VersionCode,
                     kT3HeartbeatCode, kT3AppKey, kT3PublicKeyPEM, &err);
        if (gVerify) t3a_log(@"✅ RSA 模式初始化成功");
        else         t3a_log(@"⚠️ RSA 模式失败(%@)，退化 base64 模式", [err localizedDescription]);
    }

    // ② 自定义 base64 模式（兜底）
    if (!gVerify) {
        SEL sB64 = NSSelectorFromString(@"initWithLoginCode:noticeCode:versionCode:heartbeatCode:appkey:base64Charset:");
        if ([cls instancesRespondToSelector:sB64]) {
            id (*fn)(id, SEL, NSString*, NSString*, NSString*, NSString*, NSString*, NSString*) =
                (id (*)(id, SEL, NSString*, NSString*, NSString*, NSString*, NSString*, NSString*))(void *)objc_msgSend;
            gVerify = fn([cls alloc], sB64, kT3LoginCode, kT3NoticeCode, kT3VersionCode,
                         kT3HeartbeatCode, kT3AppKey, kT3Base64Charset);
            if (gVerify) t3a_log(@"✅ base64 模式初始化成功");
        }
    }
    if (!gVerify) { t3a_log(@"❌ SDK 初始化失败（两种模式都不行）"); return nil; }

    SEL sChk = NSSelectorFromString(@"checkInit:");
    if ([gVerify respondsToSelector:sChk]) {
        BOOL (*fn)(id, SEL, NSError**) = (BOOL (*)(id, SEL, NSError**))(void *)objc_msgSend;
        NSError *e = nil;
        t3a_log(@"checkInit = %@ %@", fn(gVerify, sChk, &e) ? @"YES" : @"NO", [e localizedDescription] ?: @"");
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
            t3a_log(@"校验卡密=%@ imei=%@", kami, imei);

            T3LoginResult *r = nil;
            SEL s = NSSelectorFromString(@"loginWithKami:imei:");
            if ([gVerify respondsToSelector:s]) {
                T3LoginResult *(*fn)(id, SEL, NSString*, NSString*) =
                    (T3LoginResult *(*)(id, SEL, NSString*, NSString*))(void *)objc_msgSend;
                r = fn(gVerify, s, kami, imei);
            }
            BOOL ok = (r && [r success]);
            NSString *msg = ok ? @"验证成功" : ([[r error] length] ? [r error] : @"验证失败，请检查卡密");

            if (ok) {
                if ([r statecode]) gStatecode = [r statecode];
                if ([r endTime])   gEndTime   = [r endTime];
                t3a_writeState();
            }
            t3a_log(@"结果 ok=%d msg=%@ end=%@ statecode=%@", ok, msg, [r endTime], [r statecode]);

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
    if (gAuthorized) return;
    if (gLockWindow) { [gLockWindow makeKeyAndVisible]; return; }
    if (gLockShown) return;
    gLockShown = YES;

    UIWindow *w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    w.windowLevel = UIWindowLevelAlert + 20;          // 盖过 app 自己的一切窗口
    w.backgroundColor = [UIColor colorWithWhite:0.07 alpha:1];
    w.rootViewController = [T3ALockVC new];
    [w makeKeyAndVisible];
    gLockWindow = w;
    t3a_log(@"🔒 门禁窗口已建立");
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
                t3a_log(@"心跳正常，到期 %@", gEndTime);
            } else {
                t3a_log(@"心跳失败：%@", [r error] ?: @"?");
            }
        }
    });
    dispatch_resume(timer);
}

#pragma mark ================= AppDelegate 兜底 =================

static void t3a_appDidFinishLaunching(id self, SEL _cmd, UIApplication *app, NSDictionary *opts) {
    if (gOrigDidFinishLaunching) {
        ((void (*)(id, SEL, UIApplication*, NSDictionary*))gOrigDidFinishLaunching)(self, _cmd, app, opts);
    }
    t3a_log(@"didFinishLaunching 归来，重新抬起门禁窗口");
    if (!gAuthorized) t3a_showLock();
}

static void t3a_installDelegateHook(void) {
    Class c = NSClassFromString(@"MainApplicationDelegate");
    if (!c) {
        NSString *n = [NSBundle mainBundle].infoDictionary[@"NSPrincipalClass"];
        if (n) c = NSClassFromString(n);
    }
    if (!c) {
        id d = [UIApplication sharedApplication].delegate;
        if (d) c = object_getClass(d);
    }
    if (!c) { t3a_log(@"⚠️ 找不到 AppDelegate，跳过兜底 hook"); return; }

    SEL s = NSSelectorFromString(@"application:didFinishLaunchingWithOptions:");
    Method m = class_getInstanceMethod(c, s);
    if (!m) { t3a_log(@"⚠️ %@ 没有 didFinishLaunching", c); return; }
    gOrigDidFinishLaunching = method_getImplementation(m);
    class_replaceMethod(c, s, (IMP)t3a_appDidFinishLaunching, method_getTypeEncoding(m));
    t3a_log(@"✅ 已挂 %@ didFinishLaunchingWithOptions: (orig=%p)", c, gOrigDidFinishLaunching);
}

#pragma mark ================= 安装（绝不让异常逃出去） =================

static void t3a_install(void) {
    @autoreleasepool {
        t3a_log(@"=== T3Adapter v3 启动 ===");
        t3a_readState();
        t3a_log(@"缓存卡密=%@ 到期=%@", gKami ?: @"(无)", gEndTime ?: @"(无)");

        t3a_showLock();                 // ① 先把遮罩铺上
        t3a_installDelegateHook();      // ② 防被 app 的 window 盖住
        t3a_startHeartbeat();           // ③ 心跳

        if (gQueue == NULL) gQueue = dispatch_queue_create("com.t3a.verify", DISPATCH_QUEUE_SERIAL);
        dispatch_async(gQueue, ^{ t3a_makeVerify(); });   // ④ SDK 预热

        t3a_log(@"=== T3Adapter 安装完成 ===");
    }
}

__attribute__((constructor))
static void t3a_ctor(void) {
    if ([NSThread isMainThread]) t3a_install();
    else dispatch_async(dispatch_get_main_queue(), ^{ t3a_install(); });
}
