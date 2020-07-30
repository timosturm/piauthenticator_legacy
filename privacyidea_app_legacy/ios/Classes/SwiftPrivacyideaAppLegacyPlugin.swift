import Flutter
import UIKit

public class SwiftPrivacyideaAppLegacyPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "privacyidea_app_legacy", binaryMessenger: registrar.messenger())
    let instance = SwiftPrivacyideaAppLegacyPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    result("iOS " + UIDevice.current.systemVersion)
  }
}
