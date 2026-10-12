// =====================================================================
//  T3Verify.h  —  从 T3Gate.dylib 的 ObjC 元数据实体反出来的接口
//  数据来源：_work/regen_iface.py 解析 dylib 的 class_ro_t / method_list_t
//  类型编码见 _work/regen_iface.txt（例如 loginWithKami:imei: 是 @32@0:8@16@24）
//  这份是手工整理过的正确签名版
// =====================================================================
#import <Foundation/Foundation.h>

#pragma mark - 结果包装类

@interface T3Result : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, strong) NSString *error;
@property (nonatomic, strong) NSString *msg;
+ (instancetype)ok;
+ (instancetype)okWithMsg:(NSString *)msg;
+ (instancetype)fail:(NSString *)err;
@end

@interface T3LoginResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, strong) NSString *error;
@property (nonatomic, strong) NSString *kamiId;
@property (nonatomic, strong) NSString *endTime;
@property (nonatomic, strong) NSString *statecode;
@property (nonatomic, assign) int recharge;
@property (nonatomic, assign) long long useTime;
@property (nonatomic, assign) long long amount;
@property (nonatomic, assign) int available;
@property (nonatomic, strong) NSString *imei;
@property (nonatomic, assign) int change;
@property (nonatomic, strong) NSString *core;
+ (instancetype)okWithData:(id)data;
+ (instancetype)fail:(NSString *)err;
@end

@interface T3NoticeResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, strong) NSString *error;
@property (nonatomic, strong) NSString *notice;
+ (instancetype)okWithNotice:(NSString *)n;
+ (instancetype)fail:(NSString *)err;
@end

@interface T3QueryResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, strong) NSString *error;
@property (nonatomic, strong) NSString *state;
@property (nonatomic, strong) NSString *kamiId;
@property (nonatomic, strong) NSString *endTime;
@property (nonatomic, strong) NSString *line;
@property (nonatomic, assign) long long amount;
@property (nonatomic, assign) int available;
+ (instancetype)okWithData:(id)data;
+ (instancetype)fail:(NSString *)err;
@end

#pragma mark - SDK 主类（二进制里共 57 个方法，按需取用）

@interface T3Verify : NSObject

@property (nonatomic, strong) NSString *statecode;
@property (nonatomic, strong) NSString *endTime;

// —— 初始化 ——
- (instancetype)initWithLoginCode:(NSString *)loginCode
                       noticeCode:(NSString *)noticeCode
                      versionCode:(NSString *)versionCode
                    heartbeatCode:(NSString *)heartbeatCode
                           appkey:(NSString *)appkey
                    base64Charset:(NSString *)base64Charset;

- (instancetype)initRsaWithLoginCode:(NSString *)loginCode
                          noticeCode:(NSString *)noticeCode
                         versionCode:(NSString *)versionCode
                       heartbeatCode:(NSString *)heartbeatCode
                              appkey:(NSString *)appkey
                        rsaPublicKey:(NSString *)pem
                               error:(NSError **)error;

- (BOOL)checkInit:(NSError **)error;

// —— 卡密核心三件套 ——
- (T3LoginResult *)loginWithKami:(NSString *)kami imei:(NSString *)imei;
- (T3QueryResult *)queryKami:(NSString *)kami;
- (T3LoginResult *)heartbeatWithKami:(NSString *)kami statecode:(NSString *)statecode;
- (T3LoginResult *)heartbeatAnyWithStatecode:(NSString *)statecode;

// —— 公告 / 版本 / 签名 ——
- (T3NoticeResult *)getNotice;
- (id)getLatestVersion;
- (id)checkUpdateWithVer:(NSString *)ver;
- (id)getCloudDocWithToken:(NSString *)token;
- (id)appSignWithAutograph:(NSString *)autograph;

// —— 用户体系（备用）——
- (id)userRegisterWithUser:(NSString *)u pass:(NSString *)p email:(NSString *)e;
- (id)userLoginWithUser:(NSString *)u pass:(NSString *)p imei:(NSString *)i;
- (id)userHeartbeatWithUser:(NSString *)u pass:(NSString *)p statecode:(NSString *)s;
- (id)rechargeWithUser:(NSString *)u card:(NSString *)c;
- (id)kamiRechargeWithTargetKami:(NSString *)t sourceKami:(NSString *)s;
- (id)getCoreByKami:(NSString *)k;
- (id)getOnlineKamiCount;
- (id)getOnlineUserCount;

@end
