#import "NSXAppDelegate.h"
#import "NSXRootViewController.h"

BOOL NSXSkipAnimations(void) {
    return UIAccessibilityIsVoiceOverRunning() || UIAccessibilityIsReduceMotionEnabled();
}

@implementation NSXAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    _window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:[NSXRootViewController new]];
    // No large title: with our own scroll view it stayed expanded over the content after alerts
    nav.navigationBar.prefersLargeTitles = NO;
    _window.rootViewController = nav;
    [_window makeKeyAndVisible];
    if (!NSXSkipAnimations()) [self playLaunchAnimation];
    return YES;
}

- (void)playLaunchAnimation {
    UIView *root = _window.rootViewController.view;
    CGRect bounds = root.bounds;

    UIView *splash = [[UIView alloc] initWithFrame:bounds];
    splash.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    splash.backgroundColor = UIColor.systemBackgroundColor;

    // Storyboard
    UIImageView *icon = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"LaunchIcon"]];
    icon.frame = CGRectMake(0, 0, 120, 120);
    icon.center = CGPointMake(CGRectGetMidX(bounds), CGRectGetMidY(bounds) - 20);

    UILabel *title = [UILabel new];
    title.text = @"NonceSetX";
    title.font = [UIFont boldSystemFontOfSize:28];
    title.textColor = UIColor.labelColor;
    [title sizeToFit];
    title.center = CGPointMake(CGRectGetMidX(bounds), CGRectGetMaxY(icon.frame) + 24 + title.bounds.size.height / 2);

    [splash addSubview:icon];
    [splash addSubview:title];
    [root addSubview:splash];

    [UIView animateWithDuration:0.25 delay:0.15 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        icon.transform = CGAffineTransformMakeScale(0.88, 0.88);
    } completion:^(BOOL finished) {
        [UIView animateWithDuration:0.45 delay:0 options:UIViewAnimationOptionCurveEaseIn animations:^{
            icon.transform = CGAffineTransformMakeScale(4, 4);
            icon.alpha = 0;
            title.alpha = 0;
            title.transform = CGAffineTransformMakeTranslation(0, 20);
            splash.backgroundColor = [splash.backgroundColor colorWithAlphaComponent:0];
        } completion:^(BOOL done) {
            [splash removeFromSuperview];
            UIAccessibilityPostNotification(UIAccessibilityScreenChangedNotification, nil);
        }];
    }];
}

@end
