package it.netknights.piauthenticator.privacyidea_app_legacy;

import android.content.Context;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.security.GeneralSecurityException;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;


/**
 * PrivacyideaAppLegacyPlugin
 */
public class PrivacyideaAppLegacyPlugin implements FlutterPlugin, MethodCallHandler {
    /// The MethodChannel that will the communication between Flutter and native Android
    ///
    /// This local reference serves to register the plugin with the Flutter Engine and unregister it
    /// when the Flutter Engine is detached from the Activity
    private MethodChannel channel;
    private static final String METHOD_CHANNEL_ID = "it.netknights.piauthenticator.legacy";

    private static final String METHOD_SIGN = "sign";
    private static final String METHOD_VERIFY = "verify";
    private static final String METHOD_LOAD_ALL_TOKENS = "load_all_tokens";
    private static final String METHOD_LOAD_FIREBASE_CONFIG = "load_firebase_config";

    private Util util;
    private SecretKeyWrapper secretKeyWrapper;

    @Override
    public void onAttachedToEngine(FlutterPluginBinding binding) {
        onAttachedToEngine(binding.getApplicationContext(), binding.getBinaryMessenger());
    }

    private void onAttachedToEngine(Context applicationContext, BinaryMessenger messenger) {

        channel = new MethodChannel(messenger, METHOD_CHANNEL_ID);
        channel.setMethodCallHandler(this);

        try {
            secretKeyWrapper = new SecretKeyWrapper(applicationContext);
            util = new Util(secretKeyWrapper, applicationContext.getFilesDir().getAbsolutePath());
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onDetachedFromEngine(FlutterPluginBinding binding) {
        channel.setMethodCallHandler(null);
        channel = null;
    }

    // This static function is optional and equivalent to onAttachedToEngine. It supports the old
    // pre-Flutter-1.12 Android projects. You are encouraged to continue supporting
    // plugin registration via this function while apps migrate to use the new Android APIs
    // post-flutter-1.12 via https://flutter.dev/go/android-project-migration.
    //
    // It is encouraged to share logic between onAttachedToEngine and registerWith to keep
    // them functionally equivalent. Only one of onAttachedToEngine or registerWith will be called
    // depending on the user's project. onAttachedToEngine or registerWith must both be defined
    // in the same class.
    public static void registerWith(Registrar registrar) {
        final PrivacyideaAppLegacyPlugin instance = new PrivacyideaAppLegacyPlugin();
        instance.onAttachedToEngine(registrar.context(), registrar.messenger());
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {

        switch (call.method) {
            case "getPlatformVersion": // TODO Remove this method call.
                result.success("Android " + android.os.Build.VERSION.RELEASE);
                break;
            case METHOD_SIGN: // TODO implement

            case METHOD_VERIFY: // TODO implement
                result.success(true);
                break;
            case METHOD_LOAD_ALL_TOKENS:
                try {
                    result.success(util.loadTokens());
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                }
                break;
            case METHOD_LOAD_FIREBASE_CONFIG:
                try {
                    result.success(util.loadFirebaseConfig());
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                }
                break;
            default:
                result.notImplemented();
        }
    }
}
