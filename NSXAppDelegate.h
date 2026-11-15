#import <UIKit/UIKit.h>

@interface NSXAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

// VoiceOver ignores hidden / transparent views, so launch animations are skipped while it (or Reduce Motion) is on
BOOL NSXSkipAnimations(void);
