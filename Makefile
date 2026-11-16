DEBUG = 0
FINALPACKAGE = 1

THEOS_DEVICE_IP = 127.0.0.1 -p 2222

ARCHS = arm64

TARGET = iphone:16.5:15.0

THEOS_PACKAGE_SCHEME ?= rootless

INSTALL_TARGET_PROCESSES = NonceSetX

APPLICATION_NAME = NonceSetX
$(APPLICATION_NAME)_FILES = main.m NSXAppDelegate.m NSXRootViewController.m NSXRunner.m
$(APPLICATION_NAME)_FRAMEWORKS = UIKit Foundation UniformTypeIdentifiers IOKit SafariServices
$(APPLICATION_NAME)_CFLAGS = -fobjc-arc -DPACKAGE_VERSION='@"$(THEOS_PACKAGE_BASE_VERSION)"'
$(APPLICATION_NAME)_CODESIGN_FLAGS = -Sent.xml

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/application.mk

LAUNCH_SCREEN = Resources/LaunchScreen.storyboardc

before-all:: $(LAUNCH_SCREEN)

$(LAUNCH_SCREEN): LaunchScreen.storyboard
	$(ECHO_NOTHING)if xcrun --find ibtool >/dev/null 2>&1; then \
		rm -rf "$@" && xcrun ibtool --errors --warnings --minimum-deployment-target 15.0 \
			--target-device iphone --target-device ipad --compile "$@" "$<" >/dev/null; \
	else echo "ibtool not found: using the committed $@"; fi$(ECHO_END)

before-package::
	@sh x8A4-build.sh "$(THEOS_STAGING_DIR)/Applications/$(APPLICATION_NAME).app/x8A4"
	@sh nsx26-build.sh "$(THEOS_STAGING_DIR)/Applications/$(APPLICATION_NAME).app/nsx26"
