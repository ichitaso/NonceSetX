#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
static NSString *mask(id v) {
    NSString *s = [[v description] stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"[0-9A-Fa-f]{10,}" options:0 error:nil];
    return [re stringByReplacingMatchesInString:s options:0 range:NSMakeRange(0, s.length) withTemplate:@"<masked>"];
}
int main(void) {
    @autoreleasepool {
        void *ct = dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_LAZY);
        CFTypeRef (*create)(CFAllocatorRef, void *, void *) = dlsym(ct, "_CTServerConnectionCreate");
        int64_t (*copyFW)(CFTypeRef, CFStringRef *) = dlsym(ct, "_CTServerConnectionCopyFirmwareVersion");
        CFTypeRef conn = create ? create(kCFAllocatorDefault, NULL, NULL) : NULL;
        CFStringRef fw = NULL;
        int64_t r = (conn && copyFW) ? copyFW(conn, &fw) : -1;
        printf("CopyFirmwareVersion ret=0x%llx fw=%s\n", r, fw ? [(__bridge NSString *)fw UTF8String] : "(nil)");
        fflush(stdout);
        Class c = objc_getClass("CoreTelephonyClient");
        id client = ((id (*)(id, SEL, dispatch_queue_t))objc_msgSend)([c alloc], NSSelectorFromString(@"initWithQueue:"), dispatch_get_main_queue());
        printf("client=%s\n", client ? "ok" : "nil"); fflush(stdout);
        SEL sel = NSSelectorFromString(@"getMobileEquipmentInfo:");
        if ([client respondsToSelector:sel]) {
            __block BOOL done = NO;
            void (^cb)(id, NSError *) = ^(id info, NSError *err) {
                printf("getMobileEquipmentInfo: class=%s err=%s\n", info ? object_getClassName(info) : "nil", err ? mask(err).UTF8String : "none");
                if (info) printf("%s\n", mask(info).UTF8String);
                fflush(stdout);
                done = YES;
            };
            ((void (*)(id, SEL, id))objc_msgSend)(client, sel, cb);
            NSDate *limit = [NSDate dateWithTimeIntervalSinceNow:3];
            while (!done && [limit timeIntervalSinceNow] > 0) [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
            if (!done) printf("getMobileEquipmentInfo: no reply in 3s\n");
        }
    }
    return 0;
}
