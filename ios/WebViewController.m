#import "WebViewController.h"
#import <UIKit/UIKit.h>
#import <spawn.h>
#import <sys/stat.h>
#import <signal.h>
#import <errno.h>
#import <string.h>

extern void CFEarlyLog(NSString *fmt, ...);

extern char **environ;

static NSString *const kHost = @"127.0.0.1";
static NSString *const kWebHost = @"localhost";
static NSString *const kPort = @"13335";
static NSString *const kBackendName = @"cfdata-backend";

static NSString *const kBootstrapJS =
    @"(function(){"
    @"  if (window.__cfdataIOSBridge) return;"
    @"  window.__cfdataIOSBridge = true;"
    @"  var orig = window.downloadFile;"
    @"  window.downloadFile = function(content, nameBase, ext){"
    @"    try {"
    @"      localStorage.setItem('cfdata_export_content', String(content == null ? '' : content));"
    @"      localStorage.setItem('cfdata_export_meta', JSON.stringify({"
    @"        nameBase: String(nameBase || 'cfdata-results'),"
    @"        ext: String(ext || 'txt')"
    @"      }));"
    @"      window.location.href = 'cfdata-export://go';"
    @"    } catch (e) { if (typeof orig === 'function') return orig(content, nameBase, ext); }"
    @"  };"
    @"  window.CFDataIOS = {"
    @"    isDarkMode: function(){ return window.matchMedia('(prefers-color-scheme: dark)').matches; }"
    @"  };"
    @"})();";

@interface WebViewController () <UIWebViewDelegate, UIDocumentPickerDelegate>
@property (nonatomic, strong) UIWebView *webView;
@property (nonatomic, strong) UIView *overlay;
@property (nonatomic, strong) UIImageView *logoView;
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic, strong) UIButton *retryButton;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, assign) pid_t backendPid;
@property (nonatomic, assign) NSInteger retryCount;
@end

@implementation WebViewController

#pragma mark - lifecycle

- (void)viewDidLoad {
    [super viewDidLoad];
    CFEarlyLog(@"viewDidLoad enter");
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    [self buildWebView];
    CFEarlyLog(@"webview built");
    [self buildOverlay];
    CFEarlyLog(@"overlay built");
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(shutdownBackend)
                                                 name:@"CFDataWillTerminate"
                                               object:nil];
    CFEarlyLog(@"about to boot");
    [self boot];
    CFEarlyLog(@"viewDidLoad done");
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [self shutdownBackend];
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    if (@available(iOS 13.0, *)) {
        return self.traitCollection.userInterfaceStyle == UIUserInterfaceStyleDark
                   ? UIStatusBarStyleLightContent : UIStatusBarStyleDarkContent;
    }
    return UIStatusBarStyleDefault;
}

- (void)traitCollectionDidChange:(UITraitCollection *)previousTraitCollection {
    [super traitCollectionDidChange:previousTraitCollection];
    [self setNeedsStatusBarAppearanceUpdate];
}

#pragma mark - UI

- (void)buildWebView {
    UIWebView *wv = [[UIWebView alloc] initWithFrame:CGRectZero];
    wv.delegate = self;
    wv.scalesPageToFit = NO;
    wv.dataDetectorTypes = UIDataDetectorTypeNone;
    wv.backgroundColor = [UIColor systemBackgroundColor];
    wv.opaque = NO;
    wv.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:wv];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [wv.topAnchor constraintEqualToAnchor:safe.topAnchor],
        [wv.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [wv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [wv.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor],
    ]];
    self.webView = wv;
}

- (void)buildOverlay {
    UIView *overlay = [[UIView alloc] initWithFrame:CGRectZero];
    overlay.translatesAutoresizingMaskIntoConstraints = NO;
    overlay.backgroundColor = [UIColor systemBackgroundColor];

    UIImageView *logo = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"logo"]];
    logo.contentMode = UIViewContentModeScaleAspectFit;
    logo.translatesAutoresizingMaskIntoConstraints = NO;
    logo.layer.cornerRadius = 18;
    logo.clipsToBounds = YES;

    UILabel *title = [[UILabel alloc] init];
    title.text = @"CFData";
    title.font = [UIFont systemFontOfSize:26 weight:UIFontWeightSemibold];
    title.textColor = [UIColor labelColor];
    title.textAlignment = NSTextAlignmentCenter;
    title.translatesAutoresizingMaskIntoConstraints = NO;

    UILabel *status = [[UILabel alloc] init];
    status.text = @"正在启动本地服务…";
    status.font = [UIFont systemFontOfSize:13];
    status.textColor = [UIColor secondaryLabelColor];
    status.textAlignment = NSTextAlignmentCenter;
    status.numberOfLines = 0;
    status.translatesAutoresizingMaskIntoConstraints = NO;

    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    spinner.translatesAutoresizingMaskIntoConstraints = NO;
    [spinner startAnimating];

    UIButton *retry = [UIButton buttonWithType:UIButtonTypeSystem];
    [retry setTitle:@"重试" forState:UIControlStateNormal];
    retry.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightMedium];
    retry.translatesAutoresizingMaskIntoConstraints = NO;
    retry.hidden = YES;
    [retry addTarget:self action:@selector(retryTapped) forControlEvents:UIControlEventTouchUpInside];

    UITextView *log = [[UITextView alloc] init];
    log.editable = NO;
    log.selectable = YES;
    log.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    log.textColor = [UIColor secondaryLabelColor];
    log.backgroundColor = [UIColor secondarySystemBackgroundColor];
    log.layer.cornerRadius = 8;
    log.translatesAutoresizingMaskIntoConstraints = NO;
    log.hidden = YES;

    [overlay addSubview:logo];
    [overlay addSubview:title];
    [overlay addSubview:status];
    [overlay addSubview:spinner];
    [overlay addSubview:retry];
    [overlay addSubview:log];
    [self.view addSubview:overlay];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [overlay.topAnchor constraintEqualToAnchor:self.view.topAnchor],
        [overlay.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [overlay.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [overlay.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],

        [logo.centerXAnchor constraintEqualToAnchor:overlay.centerXAnchor],
        [logo.centerYAnchor constraintEqualToAnchor:overlay.centerYAnchor constant:-90],
        [logo.widthAnchor constraintEqualToConstant:76],
        [logo.heightAnchor constraintEqualToConstant:76],

        [title.topAnchor constraintEqualToAnchor:logo.bottomAnchor constant:16],
        [title.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:24],
        [title.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-24],

        [status.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:10],
        [status.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:32],
        [status.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-32],

        [spinner.topAnchor constraintEqualToAnchor:status.bottomAnchor constant:18],
        [spinner.centerXAnchor constraintEqualToAnchor:overlay.centerXAnchor],

        [retry.topAnchor constraintEqualToAnchor:spinner.bottomAnchor constant:14],
        [retry.centerXAnchor constraintEqualToAnchor:overlay.centerXAnchor],

        [log.topAnchor constraintEqualToAnchor:retry.bottomAnchor constant:18],
        [log.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:24],
        [log.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-24],
        [log.heightAnchor constraintEqualToConstant:150],
    ]];

    self.overlay = overlay;
    self.logoView = logo;
    self.titleLabel = title;
    self.statusLabel = status;
    self.spinner = spinner;
    self.retryButton = retry;
    self.logView = log;
}

#pragma mark - backend

- (NSString *)dataDirectory {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray<NSString *> *candidates = @[
        [NSTemporaryDirectory() stringByAppendingPathComponent:@"CFData"],
        @"/var/mobile/Library/CFData",
    ];
    for (NSString *path in candidates) {
        NSError *err = nil;
        if ([fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:&err]) {
            return path;
        }
    }
    return NSTemporaryDirectory();
}

- (NSString *)logPath {
    return [[self dataDirectory] stringByAppendingPathComponent:@"cfdata.log"];
}

- (void)trace:(NSString *)fmt, ... {
    va_list args;
    va_start(args, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSString *path = [[self dataDirectory] stringByAppendingPathComponent:@"trace.log"];
    FILE *fp = fopen(path.fileSystemRepresentation, "a");
    if (fp) {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"HH:mm:ss.SSS";
        fprintf(fp, "[%s] %s\n", [[df stringFromDate:[NSDate date]] UTF8String], line.UTF8String);
        fclose(fp);
    }
    NSLog(@"[CFData] %@", line);
}

- (void)setStatus:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text = text;
    });
}

- (void)boot {
    [self trace:@"boot enter"];
    self.statusLabel.text = @"正在启动本地服务…";
    self.spinner.hidden = NO;
    [self.spinner startAnimating];
    self.retryButton.hidden = YES;
    self.logView.hidden = YES;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self trace:@"looking for backend in bundle"];
        NSString *bin = [[NSBundle mainBundle] pathForResource:kBackendName ofType:nil];
        if (!bin || ![[NSFileManager defaultManager] fileExistsAtPath:bin]) {
            [self failWith:[NSString stringWithFormat:@"缺少内置后端 %@", kBackendName]];
            return;
        }
        NSString *dir = [self dataDirectory];
        [self trace:@"dataDir=%@ bin=%@", dir, bin];
        pid_t pid = [self spawnBackendAt:bin workDir:dir log:[self logPath]];
        [self trace:@"spawn returned pid=%d errno=%d", pid, errno];
        if (pid <= 0) {
            [self failWith:[NSString stringWithFormat:@"启动后端失败：%s", strerror(errno)]];
            return;
        }
        self.backendPid = pid;
        [self trace:@"backend claimed pid=%d", pid];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.statusLabel.text = @"正在连接本地服务…";
            // Load unconditionally shortly after spawn: NSURLSession polling on
            // loopback proved unreliable inside a no-sandbox app.
            self.retryCount = 0;
            [self trace:@"warm-up load (expected to fail)"];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ [self loadWebUIForce]; });
        });
        [self waitForBackend:60];
    });
}

- (pid_t)spawnBackendAt:(NSString *)binPath workDir:(NSString *)workDir log:(NSString *)logPath {
    chmod(binPath.fileSystemRepresentation, 0755);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, logPath.fileSystemRepresentation,
                                     O_WRONLY | O_CREAT | O_APPEND, 0644);
    posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDERR_FILENO);

    char *argv[] = {
        (char *)binPath.fileSystemRepresentation,
        "-host", (char *)kHost.UTF8String,
        "-port", (char *)kPort.UTF8String,
        NULL,
    };
    // posix_spawn_file_actions_addchdir_np is unavailable on iOS; chdir around the call.
    char previous[PATH_MAX] = {0};
    getcwd(previous, sizeof(previous));
    chdir(workDir.fileSystemRepresentation);
    pid_t pid = -1;
    int rc = posix_spawn(&pid, binPath.fileSystemRepresentation, &actions, NULL, argv, environ);
    if (previous[0]) chdir(previous);
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        NSLog(@"[CFData] posix_spawn rc=%d %s", rc, strerror(rc));
        errno = rc;
        return -1;
    }
    NSLog(@"[CFData] backend pid=%d", pid);
    return pid;
}

- (void)waitForBackend:(int)attempts {
    if (attempts <= 0) {
        [self failWith:@"本地服务启动超时"];
        return;
    }
    if (self.backendPid > 0 && kill(self.backendPid, 0) != 0) {
        [self failWith:@"本地服务已退出"];
        return;
    }
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"http://%@:%@/favicon.png", kHost, kPort]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.timeoutInterval = 1.5;
    req.cachePolicy = NSURLRequestReloadIgnoringLocalAndRemoteCacheData;
    [[[NSURLSession sharedSession] dataTaskWithRequest:req
                                     completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        NSInteger code = [resp isKindOfClass:[NSHTTPURLResponse class]] ? [(NSHTTPURLResponse *)resp statusCode] : 0;
        if (code >= 200 && code < 500) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self loadWebUI];
            });
            return;
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self waitForBackend:attempts - 1];
        });
    }] resume];
}

- (void)loadWebUIForce {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"http://%@:%@/", kWebHost, kPort]];
    [self trace:@"loadWebUIForce %@", url];
    [self.webView loadRequest:[NSURLRequest requestWithURL:url]];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NSString *probe = [self.webView stringByEvaluatingJavaScriptFromString:@"document.title + '|' + document.readyState + '|' + location.href"];
        [self trace:@"JS probe: %@", probe];
    });
}

- (void)loadWebUI {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self trace:@"loadWebUI after poll success url=%@", self.webView.request.URL];
        self.statusLabel.text = @"正在加载界面…";
        [self loadWebUIForce];
    });
}

- (void)shutdownBackend {
    pid_t pid = self.backendPid;
    if (pid <= 0) return;
    self.backendPid = 0;
    kill(pid, SIGTERM);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        if (kill(pid, 0) == 0) kill(pid, SIGKILL);
    });
}

#pragma mark - failure UI

- (void)failWith:(NSString *)message {
    NSLog(@"[CFData] %@", message);
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text = message;
        [self.spinner stopAnimating];
        self.retryButton.hidden = NO;
        self.logView.text = [self logTail];
        self.logView.hidden = NO;
    });
}

- (NSString *)logTail {
    NSString *text = [NSString stringWithContentsOfFile:[self logPath]
                                               encoding:NSUTF8StringEncoding
                                                  error:NULL];
    if (text.length == 0) return @"（没有后端日志输出）";
    if (text.length > 4000) text = [text substringFromIndex:text.length - 4000];
    return text;
}

- (void)retryTapped {
    [self shutdownBackend];
    self.logView.hidden = YES;
    [self boot];
}

#pragma mark - UIWebViewDelegate

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType {
    NSURL *url = request.URL;
    NSString *scheme = url.scheme.lowercaseString;
    if ([scheme isEqualToString:@"cfdata-export"]) {
        [self handleExportFromWebView:webView];
        return NO;
    }
    if ([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"]) {
        NSString *host = url.host.lowercaseString;
        if ([host isEqualToString:@"127.0.0.1"] || [host isEqualToString:@"localhost"]) return YES;
        [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
        return NO;
    }
    if ([scheme isEqualToString:@"about"] || [scheme isEqualToString:@"data"] || [scheme isEqualToString:@"blob"] || scheme.length == 0) return YES;
    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
    return NO;
}

- (void)handleExportFromWebView:(UIWebView *)webView {
    NSString *content = [webView stringByEvaluatingJavaScriptFromString:@"localStorage.getItem('cfdata_export_content') || ''"];
    NSString *metaJson = [webView stringByEvaluatingJavaScriptFromString:@"localStorage.getItem('cfdata_export_meta') || '{}'"];
    if (content.length == 0) return;

    NSDictionary *meta = nil;
    NSData *metaData = [metaJson dataUsingEncoding:NSUTF8StringEncoding];
    if (metaData) meta = [NSJSONSerialization JSONObjectWithData:metaData options:0 error:NULL];
    NSString *nameBase = [meta[@"nameBase"] isKindOfClass:[NSString class]] ? meta[@"nameBase"] : @"cfdata-results";
    NSString *ext = [meta[@"ext"] isKindOfClass:[NSString class]] ? meta[@"ext"] : @"txt";

    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"yyyyMMdd_HHmmss";
    NSString *stamp = [fmt stringFromDate:[NSDate date]];
    NSString *fileName = [NSString stringWithFormat:@"%@_%@.%@", nameBase, stamp, ext];
    fileName = [[fileName componentsSeparatedByCharactersInSet:
                 [NSCharacterSet characterSetWithCharactersInString:@"/\\:*?\"<>|"]] componentsJoinedByString:@"_"];

    NSMutableData *data = [NSMutableData data];
    [data appendData:[@"\uFEFF" dataUsingEncoding:NSUTF8StringEncoding]];
    [data appendData:[content dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:fileName];
    if (![data writeToFile:path atomically:YES]) { [self trace:@"export write failed"]; return; }
    [self trace:@"export %@ %lu bytes", fileName, (unsigned long)data.length];

    [webView stringByEvaluatingJavaScriptFromString:@"localStorage.removeItem('cfdata_export_content');localStorage.removeItem('cfdata_export_meta');"];

    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc] initForExportingURLs:@[[NSURL fileURLWithPath:path]] asCopy:YES];
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)webViewDidStartLoad:(UIWebView *)webView {
    [self trace:@"didStartLoad %@", webView.request.URL];
}

- (void)webViewDidFinishLoad:(UIWebView *)webView {
    [self trace:@"didFinishLoad %@", webView.request.URL];
    [webView stringByEvaluatingJavaScriptFromString:kBootstrapJS];
    self.retryCount = 0;
    self.overlay.hidden = YES;
    [self.view bringSubviewToFront:webView];
    NSString *probe = [webView stringByEvaluatingJavaScriptFromString:@"document.title + '|' + document.readyState"];
    [self trace:@"JS probe: %@", probe];
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error {
    [self trace:@"didFailLoad %@ %ld", error.localizedDescription, (long)error.code];
    if (error.code == NSURLErrorCancelled) return;
    self.retryCount++;
}

#pragma mark - UIDocumentPickerDelegate

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {}
- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {}

@end
