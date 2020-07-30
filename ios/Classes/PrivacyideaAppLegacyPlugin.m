#import "PrivacyideaAppLegacyPlugin.h"
#if __has_include(<privacyidea_app_legacy/privacyidea_app_legacy-Swift.h>)
#import <privacyidea_app_legacy/privacyidea_app_legacy-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "privacyidea_app_legacy-Swift.h"
#endif

@implementation PrivacyideaAppLegacyPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftPrivacyideaAppLegacyPlugin registerWithRegistrar:registrar];
}
@end
