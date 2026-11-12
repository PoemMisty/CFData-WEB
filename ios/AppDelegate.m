#import "AppDelegate.h"
#import "WebViewController.h"

extern void CFEarlyLog(NSString *fmt, ...);

@interface AppDelegate ()
@property (nonatomic, assign) UIBackgroundTaskIdentifier bgTask;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    CFEarlyLog(@"didFinishLaunching enter");
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[WebViewController alloc] init];
    [self.window makeKeyAndVisible];
    CFEarlyLog(@"window visible");
    return YES;
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    // The Go backend lives as long as the process; ask iOS for extra time so a
    // running scan is not frozen the moment the user switches apps.
    if (self.bgTask != UIBackgroundTaskInvalid) return;
    __weak typeof(self) weakSelf = self;
    self.bgTask = [application beginBackgroundTaskWithName:@"cfdata-scan" expirationHandler:^{
        __strong typeof(weakSelf) self2 = weakSelf;
        if (!self2) return;
        [application endBackgroundTask:self2.bgTask];
        self2.bgTask = UIBackgroundTaskInvalid;
    }];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    if (self.bgTask != UIBackgroundTaskInvalid) {
        [application endBackgroundTask:self.bgTask];
        self.bgTask = UIBackgroundTaskInvalid;
    }
}

- (void)applicationWillTerminate:(UIApplication *)application {
    [[NSNotificationCenter defaultCenter] postNotificationName:@"CFDataWillTerminate" object:nil];
}

@end
