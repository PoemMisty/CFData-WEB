#import <UIKit/UIKit.h>
#import "AppDelegate.h"

void CFEarlyLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    NSString *path = [dir stringByAppendingPathComponent:@"early.log"];
    FILE *fp = fopen(path.fileSystemRepresentation, "a");
    if (fp) {
        fprintf(fp, "%s\n", line.UTF8String);
        fclose(fp);
    }
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        CFEarlyLog(@"main enter tmp=%@", NSTemporaryDirectory());
        int r = UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
        CFEarlyLog(@"main exit %d", r);
        return r;
    }
}
