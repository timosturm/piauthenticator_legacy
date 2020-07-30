import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:privacyidea_app_legacy/privacyidea_app_legacy.dart';

void main() {
  const MethodChannel channel = MethodChannel('privacyidea_app_legacy');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await Legacy.platformVersion, '42');
  });
}
