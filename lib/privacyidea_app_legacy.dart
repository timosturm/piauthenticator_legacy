import 'dart:async';

import 'package:flutter/services.dart';

const String METHOD_CHANNEL_ID = "it.netknights.piauthenticator.legacy";
const String METHOD_SIGN = "sign";
const String METHOD_VERIFY = "verify";
const String METHOD_LOAD_ALL_TOKENS = "load_all_tokens";

class Legacy {
  static const MethodChannel _channel = const MethodChannel(METHOD_CHANNEL_ID);

  static Future<String> get platformVersion async {
    final String version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }

  // TODO Support the following method calls:
  //  sign(String serial, String message) -> String signedMessage
  //  verify(String serial, String signed, String signature) -> bool isValid
  //  loadAllTokens() -> List<Token> tokens

  static Future<String> sign(String serial, String message) async =>
      await _channel.invokeMethod(METHOD_SIGN, [serial, message]);

  static Future<bool> verify(
          String serial, String signedData, String signature) async =>
      await _channel
          .invokeMethod(METHOD_VERIFY, [serial, signedData, signature]);

  static Future<String> loadAllTokens(int a) async =>
      await _channel.invokeMethod(METHOD_LOAD_ALL_TOKENS);
}
