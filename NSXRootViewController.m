#import "NSXRootViewController.h"
#import "NSXAppDelegate.h"
#import "NSXRunner.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <SafariServices/SafariServices.h>
#import <dlfcn.h>
#import <sys/sysctl.h>

#define VERSION @"v1.0.0"
#define L(key) NSLocalizedString(key, nil)

static NSString *const kPresetUnc0ver = @"0x1111111111111111";
static NSString *const kPresetElectra = @"0xbd34a880be0b53f3";
static NSString *const kBlobGeneratorKey = @"BlobGenerator";
static NSString *const kBlobNameKey = @"BlobName";

static CFTypeRef (*$MGCopyAnswer)(CFStringRef);

static NSString *MGString(NSString *key) {
    if (!$MGCopyAnswer) return nil;
    CFTypeRef value = $MGCopyAnswer((__bridge CFStringRef)key);
    return value ? [NSString stringWithFormat:@"%@", CFBridgingRelease(value)] : nil;
}

// Baseband firmware from CommCenter. ChipID / CertId / BbSNUM are only given to a paired computer (lockdownd)
static NSString *BasebandFirmwareVersion(void) {
    void *ct = dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_LAZY);
    CFTypeRef (*create)(CFAllocatorRef, void *, void *) = ct ? dlsym(ct, "_CTServerConnectionCreate") : NULL;
    int64_t (*copyFirmware)(CFTypeRef, CFStringRef *) = ct ? dlsym(ct, "_CTServerConnectionCopyFirmwareVersion") : NULL;
    if (!create || !copyFirmware) return nil;
    CFTypeRef connection = create(kCFAllocatorDefault, NULL, NULL);
    if (!connection) return nil;
    CFStringRef version = NULL;
    copyFirmware(connection, &version);
    CFRelease(connection);
    return version ? CFBridgingRelease(version) : nil;
}

// IODeviceTree:/chosen is filled by iBoot and readable without kernel r/w (also on iOS 26 and palera1n)
typedef mach_port_t io_object_t;
extern const mach_port_t kIOMasterPortDefault;
extern io_object_t IORegistryEntryFromPath(mach_port_t, const char *);
extern CFTypeRef IORegistryEntryCreateCFProperty(io_object_t, CFStringRef, CFAllocatorRef, uint32_t);
extern kern_return_t IOObjectRelease(io_object_t);

static NSData *ChosenProperty(NSString *name) {
    io_object_t chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
    if (!chosen) return nil;
    id value = CFBridgingRelease(IORegistryEntryCreateCFProperty(chosen, (__bridge CFStringRef)name, kCFAllocatorDefault, 0));
    IOObjectRelease(chosen);
    return [value isKindOfClass:NSData.class] ? value : nil;
}

// The generator iBoot booted with (boot-nonce, little-endian)
static NSString *DeviceTreeGenerator(void) {
    NSData *data = ChosenProperty(@"boot-nonce");
    if (data.length != 8) return nil;
    uint64_t generator = 0;
    memcpy(&generator, data.bytes, 8);
    return [NSString stringWithFormat:@"0x%016llx", generator];
}

// A12 and later entangle the APNonce with the device, so it can't be derived from the generator alone
static BOOL IsA12OrNewer(void) {
    NSData *data = ChosenProperty(@"chip-id");
    uint32_t chip = 0;
    if (data.length >= 4) memcpy(&chip, data.bytes, 4);
    return chip >= 0x8020;
}

static NSString *ProductType(void) {
    size_t size = 0;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    char machine[size + 1];
    sysctlbyname("hw.machine", machine, &size, NULL, 0);
    machine[size] = '\0';
    return [NSString stringWithUTF8String:machine];
}

typedef NS_ENUM(NSInteger, NSXState) {
    NSXStateLoading,
    NSXStateReady,
    NSXStateNoX8A4,
    NSXStateUnsupported,
    NSXStateError,
    NSXStateLimited,
};

@interface NSXRootViewController () <UITextFieldDelegate, UIDocumentPickerDelegate>
@property (nonatomic, copy) NSString *generator;
@property (nonatomic, copy) NSString *apnonce;
@property (nonatomic, copy) NSString *cryptexNonce;
@property (nonatomic, copy) NSString *cryptexSeed;
@property (nonatomic, strong) UILabel *cryptexSeedValue;
@property (nonatomic, copy) NSString *lastLog;
@property (nonatomic, copy) NSString *setLog;
@property (nonatomic, copy) NSString *ecid;
@property (nonatomic, copy) NSString *boardConfig;
@property (nonatomic, assign) NSXState state;
@property (nonatomic, assign) BOOL busy;
@property (nonatomic, assign) BOOL showAdvanced;
@property (nonatomic, assign) BOOL showECID;
@property (nonatomic, assign) BOOL didIntro;

@property (nonatomic, strong) UIStackView *stack;
@property (nonatomic, strong) UIView *statusDot;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UILabel *generatorValue;
@property (nonatomic, strong) UILabel *apnonceValue;
@property (nonatomic, strong) UILabel *cryptexValue;
@property (nonatomic, strong) UILabel *matchLabel;
@property (nonatomic, strong) UILabel *apnonceNote;
@property (nonatomic, strong) UISegmentedControl *presetControl;
@property (nonatomic, strong) UITextField *generatorField;
@property (nonatomic, strong) UILabel *blobLabel;
@property (nonatomic, strong) UIButton *setButton;
@property (nonatomic, strong) UILabel *setSupportLabel;
@property (nonatomic, assign) BOOL setSupported;
@property (nonatomic, copy) NSString *setUnsupportedReason;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic, strong) UIStackView *advancedStack;
@property (nonatomic, strong) UIButton *advancedToggle;
@property (nonatomic, strong) UILabel *ecidValue;
@property (nonatomic, strong) UILabel *basebandValue;
@end

@implementation NSXRootViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"NonceSetX";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;

    void *gestalt = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
    if (gestalt) $MGCopyAnswer = dlsym(gestalt, "MGCopyAnswer");
    NSString *ecid = MGString(@"UniqueChipID");
    _ecid = ecid.length ? ecid : nil;
    _boardConfig = MGString(@"HWModelStr").lowercaseString;

    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(refresh)];

    [self buildUI];
    [self refresh];
}

#pragma mark - Launch animation

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    if (NSXSkipAnimations()) _didIntro = YES;
    // Hidden until the cascade runs (no flash)
    if (!_didIntro) _stack.alpha = 0;
}

// Cards rise into place one after another
- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    if (_didIntro) return;
    _didIntro = YES;
    _stack.alpha = 1;
    [_stack.arrangedSubviews enumerateObjectsUsingBlock:^(UIView *card, NSUInteger idx, BOOL *stop) {
        card.alpha = 0;
        card.transform = CGAffineTransformMakeTranslation(0, 22);
        [UIView animateWithDuration:0.5
                              delay:0.05 * idx
             usingSpringWithDamping:0.88
              initialSpringVelocity:0
                            options:UIViewAnimationOptionCurveEaseOut | UIViewAnimationOptionAllowUserInteraction
                         animations:^{
            card.alpha = 1;
            card.transform = CGAffineTransformIdentity;
        } completion:nil];
    }];
}

#pragma mark - UI building

- (void)buildUI {
    UIScrollView *scroll = [UIScrollView new];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.keyboardDismissMode = UIScrollViewKeyboardDismissModeInteractive;
    scroll.alwaysBounceVertical = YES;
    [self.view addSubview:scroll];

    _stack = [UIStackView new];
    _stack.axis = UILayoutConstraintAxisVertical;
    _stack.spacing = 16;
    _stack.translatesAutoresizingMaskIntoConstraints = NO;
    [scroll addSubview:_stack];

    UILayoutGuide *guide = self.view.readableContentGuide;
    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:self.view.topAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [_stack.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:8],
        [_stack.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-24],
        [_stack.leadingAnchor constraintEqualToAnchor:guide.leadingAnchor],
        [_stack.trailingAnchor constraintEqualToAnchor:guide.trailingAnchor],
    ]];

    // Status
    UIStackView *statusRow = [self rowStack];
    _statusDot = [UIView new];
    _statusDot.layer.cornerRadius = 6;
    [_statusDot.widthAnchor constraintEqualToConstant:12].active = YES;
    [_statusDot.heightAnchor constraintEqualToConstant:12].active = YES;
    _statusLabel = [self bodyLabel];
    _statusLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    _spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _spinner.hidesWhenStopped = YES;
    [statusRow addArrangedSubview:_statusDot];
    [statusRow addArrangedSubview:_statusLabel];
    [statusRow addArrangedSubview:_spinner];
    [_stack addArrangedSubview:[self cardWithViews:@[statusRow]]];

    // Current values
    _generatorValue = [self valueLabel];
    _apnonceValue = [self valueLabel];
    _cryptexValue = [self valueLabel];
    _matchLabel = [self bodyLabel];
    _matchLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    NSMutableArray *currentViews = [@[
        [self sectionTitle:L(@"CURRENT_TITLE")],
        [self captionLabel:L(@"GENERATOR")], [self copyRowWithLabel:_generatorValue action:@selector(copyGenerator)],
        _matchLabel,
        [self captionLabel:L(@"APNONCE")], [self copyRowWithLabel:_apnonceValue action:@selector(copyAPNonce)],
    ] mutableCopy];
    _apnonceNote = [self captionLabel:L(@"APNONCE_RECOVERY_NOTE")];
    _apnonceNote.textColor = UIColor.systemOrangeColor;
    _apnonceNote.hidden = YES;
    [currentViews addObject:_apnonceNote];
    if (@available(iOS 16, *)) {
        _cryptexSeedValue = [self valueLabel];
        [currentViews addObject:[self captionLabel:L(@"CRYPTEX_SEED")]];
        [currentViews addObject:[self copyRowWithLabel:_cryptexSeedValue action:@selector(copyCryptexSeed)]];
        [currentViews addObject:[self captionLabel:L(@"CRYPTEX_NONCE")]];
        [currentViews addObject:[self copyRowWithLabel:_cryptexValue action:@selector(copyCryptex)]];
    }
    [_stack addArrangedSubview:[self cardWithViews:currentViews]];

    // Step 1: save blobs for the current generator / APNonce pair
    NSMutableArray *saveViews = [@[
        [self stepTitle:@"1" text:L(@"SAVE_TITLE")],
        [self bodyLabelWithText:L(@"SAVE_BODY")],
        [self filledButton:L(@"COPY_TSSCHECKER") action:@selector(copyTSSChecker)],
        [self plainButton:L(@"COPY_ALL_VALUES") image:@"list.bullet.clipboard" action:@selector(copyAllValues)],
    ] mutableCopy];
    if (@available(iOS 16, *)) [saveViews addObject:[self captionLabel:L(@"SAVE_CRYPTEX_NOTE")]];
    if ([MGString(@"HasBaseband") boolValue]) [saveViews addObject:[self captionLabel:L(@"SAVE_BASEBAND_NOTE")]];
    UILabel *limitsNote = [self captionLabel:L(@"SAVE_LIMITS_NOTE")];
    limitsNote.textColor = UIColor.systemOrangeColor;
    [saveViews addObject:limitsNote];
    [_stack addArrangedSubview:[self cardWithViews:saveViews]];

    // Step 2: compare with a saved blob
    UIButton *blobButton = [self plainButton:L(@"LOAD_SHSH") image:@"doc.badge.plus" action:@selector(pickBlob)];
    _blobLabel = [self captionLabel:@""];
    [_stack addArrangedSubview:[self cardWithViews:@[
        [self stepTitle:@"2" text:L(@"COMPARE_TITLE")],
        [self bodyLabelWithText:L(@"COMPARE_BODY")],
        blobButton, _blobLabel,
    ]]];

    // Step 3: set the generator (x8A4 -S writes the NVRAM V3 entry directly; -V says whether this device is supported)
    _presetControl = [[UISegmentedControl alloc] initWithItems:@[L(@"PRESET_UNC0VER"), L(@"PRESET_ELECTRA"), L(@"PRESET_CUSTOM")]];
    [_presetControl addTarget:self action:@selector(presetChanged) forControlEvents:UIControlEventValueChanged];
    _generatorField = [UITextField new];
    _generatorField.borderStyle = UITextBorderStyleRoundedRect;
    _generatorField.placeholder = kPresetUnc0ver;
    _generatorField.font = [UIFont monospacedSystemFontOfSize:17 weight:UIFontWeightRegular];
    _generatorField.clearButtonMode = UITextFieldViewModeWhileEditing;
    _generatorField.keyboardType = UIKeyboardTypeASCIICapable;
    _generatorField.autocorrectionType = UITextAutocorrectionTypeNo;
    _generatorField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    _generatorField.returnKeyType = UIReturnKeyDone;
    _generatorField.delegate = self;
    [_generatorField addTarget:self action:@selector(generatorEdited) forControlEvents:UIControlEventEditingChanged];
    [_generatorField.heightAnchor constraintEqualToConstant:44].active = YES;
    _setButton = [self filledButton:L(@"SET_BUTTON") action:@selector(setGeneratorTapped)];
    _setSupportLabel = [self captionLabel:@""];
    [_stack addArrangedSubview:[self cardWithViews:@[
        [self stepTitle:@"3" text:L(@"SET_TITLE")],
        [self bodyLabelWithText:L(@"SET_BODY")],
        _presetControl, _generatorField, _setButton, _setSupportLabel,
    ]]];

    // Step 4: check in recovery mode
    [_stack addArrangedSubview:[self cardWithViews:@[
        [self stepTitle:@"4" text:L(@"VERIFY_TITLE")],
        [self bodyLabelWithText:L(@"VERIFY_BODY")],
    ]]];

    // Baseband (cellular models only): firmware from the device, the rest from a computer
    if ([MGString(@"HasBaseband") boolValue]) {
        _basebandValue = [self valueLabel];
        _basebandValue.text = @"…";
        [_stack addArrangedSubview:[self cardWithViews:@[
            [self sectionTitle:L(@"BASEBAND_TITLE")],
            [self captionLabel:L(@"BASEBAND_FIRMWARE")], [self copyRowWithLabel:_basebandValue action:@selector(copyBaseband)],
            [self bodyLabelWithText:L(@"BASEBAND_BODY")],
            [self plainButton:L(@"COPY_BASEBAND_COMMAND") image:@"terminal" action:@selector(copyBasebandCommand)],
        ]]];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            NSString *version = BasebandFirmwareVersion();
            dispatch_async(dispatch_get_main_queue(), ^{
                self.basebandValue.text = version.length ? version : @"—";
            });
        });
    }

    // Advanced
    _advancedToggle = [self plainButton:L(@"SHOW_ADVANCED") image:@"chevron.down" action:@selector(toggleAdvanced)];
    _ecidValue = [self valueLabel];
    UIButton *ecidButton = [self plainButton:L(@"SHOW_ECID") image:@"doc.text.magnifyingglass" action:@selector(toggleECID)];
    UILabel *model = [self valueLabel];
    model.text = [NSString stringWithFormat:@"%@ (%@)", ProductType(), self.boardConfig ?: @"?"];
    _advancedStack = [UIStackView new];
    _advancedStack.axis = UILayoutConstraintAxisVertical;
    _advancedStack.spacing = 10;
    _advancedStack.hidden = YES;
    for (UIView *view in @[
        [self captionLabel:L(@"MODEL")], model,
        [self captionLabel:L(@"ECID")], [self copyRowWithLabel:_ecidValue action:@selector(copyECID)], ecidButton,
        [self captionLabel:L(@"ADVANCED_NOTE")],
        [self plainButton:L(@"COPY_LOG") image:@"doc.on.doc" action:@selector(copyLog)],
    ]) [_advancedStack addArrangedSubview:view];
    [_stack addArrangedSubview:[self cardWithViews:@[_advancedToggle, _advancedStack]]];

    // Credits (same as QuickCC2)
    [_stack addArrangedSubview:[self cardWithViews:@[
        [self sectionTitle:L(@"CREDITS")],
        [self developerButton],
        [self plainButton:L(@"OTHER_TWEAKS") image:@"square.grid.2x2" action:@selector(openOtherTweaks)],
        [self plainButton:L(@"LICENSES") image:@"doc.text" action:@selector(showLicenses)],
    ]]];

    UILabel *footer = [self captionLabel:[NSString stringWithFormat:@"%@ %@ %@ - %@\nPowered by x8A4 (Cryptiiiic)\n© 2015-2026 Cannathea by ichitaso", ProductType(), UIDevice.currentDevice.systemName, UIDevice.currentDevice.systemVersion, VERSION]];
    footer.textAlignment = NSTextAlignmentCenter;
    [_stack addArrangedSubview:footer];

    [self loadSavedBlob];
    [self updateECID];
}

- (UIView *)cardWithViews:(NSArray<UIView *> *)views {
    UIView *card = [UIView new];
    card.backgroundColor = UIColor.secondarySystemGroupedBackgroundColor;
    card.layer.cornerRadius = 14;
    card.layer.cornerCurve = kCACornerCurveContinuous;
    UIStackView *inner = [[UIStackView alloc] initWithArrangedSubviews:views];
    inner.axis = UILayoutConstraintAxisVertical;
    inner.spacing = 10;
    inner.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:inner];
    [NSLayoutConstraint activateConstraints:@[
        [inner.topAnchor constraintEqualToAnchor:card.topAnchor constant:16],
        [inner.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-16],
        [inner.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [inner.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
    ]];
    return card;
}

- (UIStackView *)rowStack {
    UIStackView *row = [UIStackView new];
    row.axis = UILayoutConstraintAxisHorizontal;
    row.spacing = 10;
    row.alignment = UIStackViewAlignmentCenter;
    return row;
}

- (UIView *)stepTitle:(NSString *)number text:(NSString *)text {
    UIStackView *row = [self rowStack];
    UILabel *badge = [UILabel new];
    badge.text = number;
    badge.textAlignment = NSTextAlignmentCenter;
    badge.textColor = UIColor.whiteColor;
    badge.font = [UIFont systemFontOfSize:15 weight:UIFontWeightBold];
    badge.backgroundColor = self.view.tintColor;
    badge.layer.cornerRadius = 13;
    badge.clipsToBounds = YES;
    [badge.widthAnchor constraintEqualToConstant:26].active = YES;
    [badge.heightAnchor constraintEqualToConstant:26].active = YES;
    [row addArrangedSubview:badge];
    [row addArrangedSubview:[self sectionTitle:text]];
    return row;
}

- (UILabel *)sectionTitle:(NSString *)text {
    UILabel *label = [UILabel new];
    label.text = text;
    label.numberOfLines = 0;
    label.font = [UIFont systemFontOfSize:20 weight:UIFontWeightBold];
    return label;
}

- (UILabel *)bodyLabel {
    UILabel *label = [UILabel new];
    label.numberOfLines = 0;
    label.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    return label;
}

- (UILabel *)bodyLabelWithText:(NSString *)text {
    UILabel *label = [self bodyLabel];
    label.text = text;
    label.textColor = UIColor.secondaryLabelColor;
    label.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
    return label;
}

- (UILabel *)captionLabel:(NSString *)text {
    UILabel *label = [UILabel new];
    label.text = text;
    label.numberOfLines = 0;
    label.textColor = UIColor.secondaryLabelColor;
    label.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    return label;
}

- (UILabel *)valueLabel {
    UILabel *label = [UILabel new];
    label.numberOfLines = 0;
    label.font = [UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightMedium];
    return label;
}

- (UIView *)copyRowWithLabel:(UILabel *)label action:(SEL)action {
    UIStackView *row = [self rowStack];
    UIButton *copy = [UIButton buttonWithType:UIButtonTypeSystem];
    [copy setImage:[UIImage systemImageNamed:@"doc.on.doc"] forState:UIControlStateNormal];
    copy.accessibilityLabel = L(@"COPY");
    [copy addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    [copy setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    [copy setContentCompressionResistancePriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    // Hex values have no word breaks: wrap them by character so the copy button stays on screen
    label.lineBreakMode = NSLineBreakByCharWrapping;
    [label setContentCompressionResistancePriority:UILayoutPriorityDefaultLow forAxis:UILayoutConstraintAxisHorizontal];
    [row addArrangedSubview:label];
    [row addArrangedSubview:copy];
    return row;
}

- (UIButton *)filledButton:(NSString *)title action:(SEL)action {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    [button setTitle:title forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont systemFontOfSize:17 weight:UIFontWeightSemibold];
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    button.backgroundColor = self.view.tintColor;
    button.layer.cornerRadius = 12;
    [button.heightAnchor constraintEqualToConstant:50].active = YES;
    [button addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (UIButton *)plainButton:(NSString *)title image:(NSString *)image action:(SEL)action {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    [button setTitle:[@" " stringByAppendingString:title] forState:UIControlStateNormal];
    [button setImage:[UIImage systemImageNamed:image] forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightMedium];
    button.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeading;
    [button.heightAnchor constraintGreaterThanOrEqualToConstant:36].active = YES;
    [button addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (UIButton *)developerButton {
    UIImage *avatar = [UIImage imageNamed:@"ichitaso"];
    UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(29, 29)];
    avatar = [[renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx) {
        [[UIBezierPath bezierPathWithOvalInRect:CGRectMake(0, 0, 29, 29)] addClip];
        [avatar drawInRect:CGRectMake(0, 0, 29, 29)];
    }] imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];

    UIButtonConfiguration *config = [UIButtonConfiguration plainButtonConfiguration];
    config.image = avatar;
    config.imagePadding = 10;
    config.title = L(@"DEVELOPED_BY");
    config.subtitle = @"@ichitaso";
    config.contentInsets = NSDirectionalEdgeInsetsZero;
    UIButton *button = [UIButton buttonWithConfiguration:config primaryAction:nil];
    button.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeading;
    [button addTarget:self action:@selector(openDeveloper:) forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (UIButton *)destructiveButton:(NSString *)title action:(SEL)action {
    UIButton *button = [self plainButton:title image:@"trash" action:action];
    button.tintColor = UIColor.systemRedColor;
    return button;
}

#pragma mark - State

- (void)setBusy:(BOOL)busy {
    _busy = busy;
    busy ? [self.spinner startAnimating] : [self.spinner stopAnimating];
    self.navigationItem.rightBarButtonItem.enabled = !busy;
    self.setButton.enabled = !busy && self.state == NSXStateReady && self.setSupported;
    self.setButton.alpha = self.setButton.enabled ? 1.0 : 0.4;
}

- (void)updateStatus {
    UIColor *color;
    NSString *text;
    switch (self.state) {
        case NSXStateLoading: color = UIColor.systemGrayColor; text = L(@"STATUS_LOADING"); break;
        case NSXStateReady: color = UIColor.systemGreenColor; text = L(@"STATUS_READY"); break;
        case NSXStateNoX8A4: color = UIColor.systemRedColor; text = L(@"STATUS_NO_X8A4"); break;
        case NSXStateUnsupported: color = UIColor.systemOrangeColor; text = L(@"STATUS_UNSUPPORTED"); break;
        case NSXStateError: color = UIColor.systemRedColor; text = L(@"STATUS_ERROR"); break;
        case NSXStateLimited: color = UIColor.systemOrangeColor; text = L(@"STATUS_LIMITED"); break;
    }
    self.apnonceNote.hidden = !(self.state == NSXStateLimited && !self.apnonce && IsA12OrNewer());
    self.statusDot.backgroundColor = color;
    self.statusLabel.text = text;

    NSString *none = self.state == NSXStateLoading ? @"…" : @"—";
    self.generatorValue.text = self.generator ?: none;
    self.apnonceValue.text = self.apnonce ?: none;
    self.cryptexValue.text = self.cryptexNonce ?: none;
    self.cryptexSeedValue.text = self.cryptexSeed ? [@"0x" stringByAppendingString:self.cryptexSeed] : none;

    NSString *blobGenerator = [NSUserDefaults.standardUserDefaults stringForKey:kBlobGeneratorKey];
    if (blobGenerator && self.generator) {
        BOOL match = [blobGenerator caseInsensitiveCompare:self.generator] == NSOrderedSame;
        self.matchLabel.text = match ? L(@"MATCH_OK") : L(@"MATCH_NG");
        self.matchLabel.textColor = match ? UIColor.systemGreenColor : UIColor.systemOrangeColor;
        self.matchLabel.hidden = NO;
    } else {
        self.matchLabel.hidden = YES;
    }

    if (self.state != NSXStateReady) {
        self.setSupportLabel.text = nil;
    } else if (self.setSupported) {
        self.setSupportLabel.text = L(@"SET_SUPPORTED");
        self.setSupportLabel.textColor = UIColor.secondaryLabelColor;
    } else {
        self.setSupportLabel.text = [NSString stringWithFormat:L(@"SET_UNSUPPORTED"), self.setUnsupportedReason ?: @"?"];
        self.setSupportLabel.textColor = UIColor.systemOrangeColor;
    }
    self.busy = self.busy;
}

- (BOOL)isSupportedVersion {
    NSOperatingSystemVersion v = NSProcessInfo.processInfo.operatingSystemVersion;
    // x8A4: 15.0 - 18.4 (NVRAM write via nsx26 on 18.x), nsx26: 18.5+ and 26
    return v.majorVersion == 26 || (v.majorVersion >= 15 && v.majorVersion <= 18);
}

#pragma mark - x8A4

- (void)runArguments:(NSArray *)arguments completion:(void (^)(NSXResult *result))completion {
    if (self.busy) return;
    self.busy = YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSXResult *result = [NSXRunner runWithArguments:arguments];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.busy = NO;
            self.lastLog = result.output;
            // Keep the set log; the refresh that follows replaces lastLog
            if ([arguments containsObject:@"-S"]) self.setLog = result.output;
            completion(result);
            [self updateStatus];
        });
    });
}

// Without x8A4 (unsupported iOS, palera1n, ...) the generator still comes from the device tree
- (void)showDeviceTreeOnly:(NSXState)fallback {
    self.generator = DeviceTreeGenerator();
    self.state = self.generator ? NSXStateLimited : fallback;
    [self updateStatus];
}

- (void)refresh {
    if (![NSXRunner toolPath]) {
        [self showDeviceTreeOnly:NSXStateNoX8A4];
        return;
    }
    if (![self isSupportedVersion]) {
        [self showDeviceTreeOnly:NSXStateUnsupported];
        return;
    }
    self.state = NSXStateLoading;
    [self updateStatus];
    NSMutableArray *args = [@[@"-g", @"-n", @"-V"] mutableCopy];
    // Cryptex1 exists from iOS 16
    if (@available(iOS 16, *)) [args addObjectsFromArray:@[@"-x", @"-t"]];
    [self runArguments:args completion:^(NSXResult *result) {
        self.cryptexSeed = [NSXRunner firstMatch:@"Got cryptex seed \\(0x([0-9a-fA-F]+)\\)" inString:result.output].lowercaseString;
        self.generator = [NSXRunner firstMatch:@"APNonce generator\\((0x[0-9a-fA-F]+)\\)" inString:result.output].lowercaseString;
        self.apnonce = [NSXRunner firstMatch:@"Got APNonce \\(0x([0-9a-fA-F]+)\\)" inString:result.output].lowercaseString;
        self.cryptexNonce = [NSXRunner firstMatch:@"Got cryptex nonce \\(0x([0-9a-fA-F]+)\\)" inString:result.output].lowercaseString;
        self.setSupported = [result.output containsString:@"NSX_V3: SUPPORTED"];
        self.setUnsupportedReason = [NSXRunner firstMatch:@"NSX_V3: UNSUPPORTED \\((.*)\\)" inString:result.output];
        if (self.generator || self.apnonce) {
            self.state = NSXStateReady;
        } else {
            self.generator = DeviceTreeGenerator();
            self.state = self.generator ? NSXStateLimited : NSXStateError;
        }
    }];
}

- (void)setGeneratorTapped {
    [self.generatorField resignFirstResponder];
    NSString *generator = [self.generatorField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].lowercaseString;
    if (!generator.length) generator = self.generatorField.placeholder;
    if (![NSXRunner isValidGenerator:generator]) {
        [self alertWithTitle:L(@"INVALID_TITLE") message:L(@"INVALID_BODY")];
        return;
    }
    if ([generator isEqualToString:self.generator]) {
        [self alertWithTitle:L(@"ALREADY_SET_TITLE") message:generator];
        return;
    }
    UIAlertController *confirm = [UIAlertController alertControllerWithTitle:L(@"CONFIRM_SET_TITLE")
                                                                     message:[NSString stringWithFormat:L(@"CONFIRM_SET_BODY"), self.generator ?: @"?", generator]
                                                              preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:L(@"CANCEL") style:UIAlertActionStyleCancel handler:nil]];
    [confirm addAction:[UIAlertAction actionWithTitle:L(@"COPY_CURRENT_AND_CANCEL") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self copyGenerator];
    }]];
    [confirm addAction:[UIAlertAction actionWithTitle:L(@"SET") style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        // -S never touches AppleMobileApNonce (x8A4 -s clears and regenerates the real generator first)
        [self runArguments:@[@"-S", generator] completion:^(NSXResult *result) {
            if ([result.output containsString:@"NSX_V3: OK"]) {
                [self alertWithTitle:L(@"DONE") message:L(@"SET_DONE_BODY")];
            } else {
                NSString *reason = [NSXRunner firstMatch:@"NSX_V3: (?:UNSUPPORTED|FAILED) \\((.*)\\)" inString:result.output];
                [self alertWithTitle:L(@"FAILED") message:[NSString stringWithFormat:L(@"SET_FAILED_BODY"), reason ?: result.output]];
            }
            [self refresh];
        }];
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

#pragma mark - Generator input

- (void)presetChanged {
    if (self.presetControl.selectedSegmentIndex == 0) self.generatorField.text = kPresetUnc0ver;
    else if (self.presetControl.selectedSegmentIndex == 1) self.generatorField.text = kPresetElectra;
    else {
        self.generatorField.text = @"";
        [self.generatorField becomeFirstResponder];
    }
}

- (void)generatorEdited {
    NSString *text = self.generatorField.text.lowercaseString;
    if ([text isEqualToString:kPresetUnc0ver]) self.presetControl.selectedSegmentIndex = 0;
    else if ([text isEqualToString:kPresetElectra]) self.presetControl.selectedSegmentIndex = 1;
    else self.presetControl.selectedSegmentIndex = 2;
}

- (void)pickBlob {
    NSMutableArray *types = [NSMutableArray array];
    for (NSString *ext in @[@"shsh2", @"shsh", @"plist"]) {
        UTType *type = [UTType typeWithFilenameExtension:ext];
        if (type) [types addObject:type];
    }
    [types addObject:UTTypeData];
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:types asCopy:YES];
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;
    BOOL scoped = [url startAccessingSecurityScopedResource];
    NSData *data = [NSData dataWithContentsOfURL:url];
    if (scoped) [url stopAccessingSecurityScopedResource];

    NSDictionary *blob = data ? [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:nil] : nil;
    NSString *generator = [blob isKindOfClass:NSDictionary.class] ? blob[@"generator"] : nil;
    if (![generator isKindOfClass:NSString.class] || ![NSXRunner isValidGenerator:generator.lowercaseString]) {
        [self alertWithTitle:L(@"BLOB_NO_GENERATOR_TITLE") message:L(@"BLOB_NO_GENERATOR_BODY")];
        return;
    }
    generator = generator.lowercaseString;
    [NSUserDefaults.standardUserDefaults setObject:generator forKey:kBlobGeneratorKey];
    [NSUserDefaults.standardUserDefaults setObject:url.lastPathComponent forKey:kBlobNameKey];
    // Step 3 writes the blob's generator back
    self.generatorField.text = generator;
    [self generatorEdited];
    [self loadSavedBlob];
    [self updateStatus];
}

- (void)loadSavedBlob {
    NSString *name = [NSUserDefaults.standardUserDefaults stringForKey:kBlobNameKey];
    NSString *generator = [NSUserDefaults.standardUserDefaults stringForKey:kBlobGeneratorKey];
    self.blobLabel.hidden = !generator;
    if (generator) self.blobLabel.text = [NSString stringWithFormat:L(@"BLOB_LOADED"), name ?: @"SHSH", generator];
    if (!self.generatorField.text.length) {
        self.presetControl.selectedSegmentIndex = 0;
        self.generatorField.text = kPresetUnc0ver;
    }
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

#pragma mark - Advanced

- (void)toggleAdvanced {
    self.showAdvanced = !self.showAdvanced;
    [self.advancedToggle setTitle:[@" " stringByAppendingString:self.showAdvanced ? L(@"HIDE_ADVANCED") : L(@"SHOW_ADVANCED")] forState:UIControlStateNormal];
    [self.advancedToggle setImage:[UIImage systemImageNamed:self.showAdvanced ? @"chevron.up" : @"chevron.down"] forState:UIControlStateNormal];
    [UIView animateWithDuration:0.25 animations:^{
        self.advancedStack.hidden = !self.showAdvanced;
        [self.stack layoutIfNeeded];
    }];
}

- (void)toggleECID {
    self.showECID = !self.showECID;
    [self updateECID];
}

- (void)updateECID {
    if (!self.ecid) {
        self.ecidValue.text = @"—";
        return;
    }
    NSString *hex = [NSString stringWithFormat:@"0x%llX", strtoull(self.ecid.UTF8String, NULL, 10)];
    self.ecidValue.text = self.showECID ? [NSString stringWithFormat:@"%@\n%@", self.ecid, hex] : @"••••••••••••";
}

- (NSString *)tsscheckerCommand {
    NSMutableString *cmd = [NSMutableString stringWithFormat:@"./tsschecker -d %@", ProductType()];
    if (self.boardConfig.length) [cmd appendFormat:@" -B %@", self.boardConfig];
    if (self.ecid.length) [cmd appendFormat:@" -e %@", self.ecid];
    if (self.generator.length) [cmd appendFormat:@" --generator %@", self.generator];
    if (self.apnonce.length) [cmd appendFormat:@" --apnonce %@", self.apnonce];
    else if (IsA12OrNewer()) [cmd appendString:@" --apnonce <NONC>"];
    // Cryptex1 (iOS 16+): seed with 0x, nonce without (needs a Cryptex1-capable tsschecker)
    if (self.cryptexSeed.length && self.cryptexNonce.length) [cmd appendFormat:@" -x 0x%@ -t %@ -E", self.cryptexSeed, self.cryptexNonce];
    [cmd appendString:@" -l -s"];
    // Cellular models: the BbSNUM is only readable from a computer, so the command reads it there (base64 -> hex).
    // Wi-Fi models skip the baseband ticket
    if ([MGString(@"HasBaseband") boolValue]) {
        NSString *udid = MGString(@"UniqueDeviceID");
        [cmd appendFormat:@" -c $(ideviceinfo%@ -k BasebandSerialNumber | base64 -d | xxd -p | tr -d '\\n')", udid.length ? [@" -u " stringByAppendingString:udid] : @""];
    } else {
        [cmd appendString:@" -b"];
    }
    return cmd;
}

#pragma mark - Credits

- (void)openURLInBrowser:(NSString *)url {
    [self presentViewController:[[SFSafariViewController alloc] initWithURL:[NSURL URLWithString:url]] animated:YES completion:nil];
}

- (void)openOtherTweaks {
    [self openURLInBrowser:@"https://cydia.ichitaso.com/donation.html"];
}

// Acknowledgements.txt: the license texts of x8A4, ChOma and XPF
- (void)showLicenses {
    UIViewController *vc = [UIViewController new];
    vc.title = L(@"LICENSES");
    UITextView *text = [UITextView new];
    text.editable = NO;
    text.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    text.textContainerInset = UIEdgeInsetsMake(16, 12, 16, 12);
    text.text = [NSString stringWithContentsOfFile:[NSBundle.mainBundle pathForResource:@"Acknowledgements" ofType:@"txt"] encoding:NSUTF8StringEncoding error:nil];
    vc.view = text;
    [self.navigationController pushViewController:vc animated:YES];
}

- (void)openDeveloper:(UIButton *)sender {
    UIApplication *app = UIApplication.sharedApplication;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:L(@"FOLLOW"), @"ichitaso"]
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    if ([app canOpenURL:[NSURL URLWithString:@"twitter://"]]) {
        [sheet addAction:[UIAlertAction actionWithTitle:L(@"OPEN_IN_X") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            [app openURL:[NSURL URLWithString:@"twitter://user?screen_name=ichitaso"] options:@{} completionHandler:nil];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:L(@"OPEN_X_IN_BROWSER") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self openURLInBrowser:@"https://x.com/ichitaso"];
    }]];
    if ([app canOpenURL:[NSURL URLWithString:@"bluesky://"]]) {
        [sheet addAction:[UIAlertAction actionWithTitle:L(@"OPEN_IN_BLUESKY") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            [app openURL:[NSURL URLWithString:@"bluesky://profile/ichitaso.com"] options:@{} completionHandler:nil];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:L(@"OPEN_BLUESKY_IN_BROWSER") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self openURLInBrowser:@"https://bsky.app/profile/ichitaso.com"];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:L(@"CANCEL") style:UIAlertActionStyleCancel handler:nil]];
    // iPad: anchor the sheet to the button
    sheet.popoverPresentationController.sourceView = sender;
    sheet.popoverPresentationController.sourceRect = sender.bounds;
    [self presentViewController:sheet animated:YES completion:nil];
}

#pragma mark - Copy

- (void)alertWithTitle:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)copyString:(NSString *)string {
    if (!string.length) return;
    UIPasteboard.generalPasteboard.string = string;
    [[UINotificationFeedbackGenerator new] notificationOccurred:UINotificationFeedbackTypeSuccess];
    [self alertWithTitle:L(@"COPIED") message:string];
}

- (void)copyGenerator {
    [self copyString:self.generator];
}

- (void)copyAPNonce {
    [self copyString:self.apnonce];
}

- (void)copyCryptex {
    [self copyString:self.cryptexNonce];
}

- (void)copyCryptexSeed {
    if (self.cryptexSeed) [self copyString:[@"0x" stringByAppendingString:self.cryptexSeed]];
}

- (void)copyECID {
    if (self.showECID) [self copyString:self.ecid];
}

- (void)copyTSSChecker {
    [self copyString:[self tsscheckerCommand]];
}

- (void)copyAllValues {
    NSMutableString *values = [NSMutableString string];
    void (^add)(NSString *, NSString *) = ^(NSString *name, NSString *value) { if (value.length) [values appendFormat:@"%@: %@\n", name, value]; };
    add(@"Device", ProductType());
    add(@"BoardConfig", self.boardConfig);
    add(@"ECID", self.ecid);
    add(@"Generator", self.generator);
    add(@"APNonce", self.apnonce);
    add(@"Cryptex1 Seed", self.cryptexSeed ? [@"0x" stringByAppendingString:self.cryptexSeed] : nil);
    add(@"Cryptex1 Nonce (Entangled Nonce)", self.cryptexNonce);
    add(@"Baseband Firmware", [self.basebandValue.text isEqualToString:@"—"] ? nil : self.basebandValue.text);
    [self copyString:values];
}

- (void)copyLog {
    if (!self.setLog.length) {
        [self copyString:self.lastLog];
        return;
    }
    [self copyString:[NSString stringWithFormat:@"%@\n--- set ---\n%@", self.lastLog ?: @"", self.setLog]];
}

- (void)copyBaseband {
    if (![self.basebandValue.text isEqualToString:@"—"]) {
        [self copyString:self.basebandValue.text];
    }
}

- (void)copyBasebandCommand {
    [self copyString:@"ideviceinfo | grep -E '^Baseband(Version|ChipID|CertId|SerialNumber):'"];
}

@end
