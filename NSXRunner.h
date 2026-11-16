#import <Foundation/Foundation.h>

@interface NSXResult : NSObject
@property (nonatomic, assign) int status;
@property (nonatomic, copy) NSString *output;
@end

// Runs the bundled x8A4 CLI (nsx26 on iOS 18.5+ / 26, and for NVRAM writes on 18.0 - 18.4) as root and parses what it prints
@interface NSXRunner : NSObject
+ (NSString *)jbroot;
+ (NSString *)toolPath;
+ (NSXResult *)runWithArguments:(NSArray<NSString *> *)arguments;
+ (NSString *)firstMatch:(NSString *)pattern inString:(NSString *)string;
+ (BOOL)isValidGenerator:(NSString *)generator;
@end
