#import "NSXRunner.h"
#import <spawn.h>
#import <sys/wait.h>

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t *__restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t *__restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t *__restrict, uid_t);

@implementation NSXResult
@end

@implementation NSXRunner

// The app lives at <jbroot>/Applications/NonceSetX.app on both rootless and roothide
+ (NSString *)jbroot {
    return NSBundle.mainBundle.bundlePath.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
}

+ (NSString *)nsx26Path {
    NSString *nsx26 = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"nsx26"];
    NSString *libjb = [self.jbroot stringByAppendingPathComponent:@"basebin/libjailbreak.dylib"];
    BOOL ok = [NSFileManager.defaultManager isExecutableFileAtPath:nsx26] && [NSFileManager.defaultManager fileExistsAtPath:libjb];
    return ok ? nsx26 : nil;
}

+ (NSString *)toolPath {
    // x8A4 supports up to 18.4; nsx26 does the same with Dopamine's libjailbreak on 18.5+ and 26
    NSOperatingSystemVersion v = NSProcessInfo.processInfo.operatingSystemVersion;
    if (v.majorVersion > 18 || (v.majorVersion == 18 && v.minorVersion >= 5)) return [self nsx26Path];
    NSArray *candidates = @[
        // Bundled build (x8A4/, patched for Dopamine 3)
        [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"x8A4"],
        [self.jbroot stringByAppendingPathComponent:@"usr/bin/x8A4"],
        @"/var/jb/usr/bin/x8A4",
    ];
    for (NSString *path in candidates) {
        if ([NSFileManager.defaultManager isExecutableFileAtPath:path]) return path;
    }
    return nil;
}

// iOS 18.0 - 18.4: x8A4 reads the values but can't find IODTNVRAM, so -V / -S go to nsx26
+ (NSString *)nvramToolPath {
    NSOperatingSystemVersion v = NSProcessInfo.processInfo.operatingSystemVersion;
    return v.majorVersion == 18 && v.minorVersion < 5 ? [self nsx26Path] : nil;
}

+ (NSXResult *)runWithArguments:(NSArray<NSString *> *)arguments {
    NSString *nvramTool = [self nvramToolPath];
    if (!nvramTool || ![self toolPath]) return [self runTool:[self toolPath] arguments:arguments];
    NSMutableArray *rest = [NSMutableArray array], *nvram = [NSMutableArray array];
    for (NSUInteger i = 0; i < arguments.count; i++) {
        NSString *a = arguments[i];
        if ([a isEqualToString:@"-V"]) [nvram addObject:a];
        else if ([a isEqualToString:@"-S"]) {
            [nvram addObject:a];
            if (i + 1 < arguments.count) [nvram addObject:arguments[++i]];
        } else [rest addObject:a];
    }
    if (!nvram.count) return [self runTool:[self toolPath] arguments:arguments];
    NSXResult *second = [self runTool:nvramTool arguments:nvram];
    if (!rest.count) return second;
    NSXResult *result = [self runTool:[self toolPath] arguments:rest];
    result.status = result.status ?: second.status;
    result.output = [NSString stringWithFormat:@"%@\n--- nsx26 ---\n%@", result.output, second.output];
    return result;
}

+ (NSXResult *)runTool:(NSString *)path arguments:(NSArray<NSString *> *)arguments {
    NSXResult *result = [NSXResult new];
    if (!path) {
        result.status = -1;
        result.output = @"x8A4 was not found. Reinstall NonceSetX.";
        return result;
    }

    int fds[2];
    if (pipe(fds) != 0) {
        result.status = -1;
        result.output = @"pipe() failed";
        return result;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, fds[0]);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);

    NSUInteger argc = arguments.count + 1;
    char **argv = calloc(argc + 1, sizeof(char *));
    argv[0] = (char *)path.fileSystemRepresentation;
    for (NSUInteger i = 0; i < arguments.count; i++) argv[i + 1] = (char *)arguments[i].UTF8String;

    pid_t pid = 0;
    int ret = posix_spawn(&pid, path.fileSystemRepresentation, &actions, &attr, argv, NULL);
    free(argv);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    close(fds[1]);

    if (ret != 0) {
        close(fds[0]);
        result.status = -1;
        result.output = [NSString stringWithFormat:@"Failed to run %@: %s", path.lastPathComponent, strerror(ret)];
        return result;
    }

    NSMutableData *data = [NSMutableData data];
    char buf[4096];
    ssize_t n;
    while ((n = read(fds[0], buf, sizeof(buf))) > 0) [data appendBytes:buf length:n];
    close(fds[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    result.status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    result.output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
    return result;
}

+ (NSString *)firstMatch:(NSString *)pattern inString:(NSString *)string {
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
    NSTextCheckingResult *match = [regex firstMatchInString:string options:0 range:NSMakeRange(0, string.length)];
    if (!match || match.numberOfRanges < 2) return nil;
    return [string substringWithRange:[match rangeAtIndex:1]];
}

// Same rule as NonceSet143: 0x + 16 hex digits
+ (BOOL)isValidGenerator:(NSString *)generator {
    return [self firstMatch:@"^(0x[0-9a-fA-F]{16})$" inString:generator] != nil;
}

@end
