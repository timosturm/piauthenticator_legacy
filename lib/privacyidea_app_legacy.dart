import 'dart:async';

import 'package:flutter/services.dart';

const String METHOD_CHANNEL_ID = "it.netknights.piauthenticator.legacy";

class PrivacyideaAppLegacy {
  static const MethodChannel _channel = const MethodChannel(METHOD_CHANNEL_ID);

  static Future<String> get platformVersion async {
    final String version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }
}
