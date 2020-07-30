import 'dart:async';

import 'package:flutter/services.dart';

class PrivacyideaAppLegacy {
  static const MethodChannel _channel =
      const MethodChannel('privacyidea_app_legacy');

  static Future<String> get platformVersion async {
    final String version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }

  
}
