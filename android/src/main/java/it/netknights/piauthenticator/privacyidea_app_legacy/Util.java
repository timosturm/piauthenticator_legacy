/*
 * Part of this code like writeFile and readFile is based on the
 * Android Open Source Project
 *
 * Copyright (C) 2013 The Android Open Source Project
 *
 * privacyIDEA Authenticator
 *
 * Authors: Nils Behlen <nils.behlen@netknights.it>
 * Copyright (c) 2017-2019 NetKnights GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package it.netknights.piauthenticator.privacyidea_app_legacy;

import android.util.Base64;
import android.util.Log;

import org.apache.commons.codec.binary.Base32;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import static it.netknights.piauthenticator.privacyidea_app_legacy.AppConstants.CRYPT_ALGORITHM;
import static it.netknights.piauthenticator.privacyidea_app_legacy.AppConstants.DATAFILE;
import static it.netknights.piauthenticator.privacyidea_app_legacy.AppConstants.FB_CONFIG_FILE;
import static it.netknights.piauthenticator.privacyidea_app_legacy.AppConstants.IV_LENGTH;
import static it.netknights.piauthenticator.privacyidea_app_legacy.AppConstants.KEYFILE;
import static it.netknights.piauthenticator.privacyidea_app_legacy.AppConstants.PUBKEYFILE;
import static it.netknights.piauthenticator.privacyidea_app_legacy.AppConstants.SIGNING_ALGORITHM;
import static it.netknights.piauthenticator.privacyidea_app_legacy.AppConstants.TAG;

public class Util {

    private String baseFilePath;
    private SecretKeyWrapper secretKeyWrapper;
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public Util(SecretKeyWrapper secretKeyWrapper, String baseFilePath) {
        this.baseFilePath = baseFilePath;
        this.secretKeyWrapper = secretKeyWrapper;
    }

    public Util() {
    }

    // TODO Rewrite

    /**
     * This Method loads the encrypted saved tokens, in the progress the Secret Key is unwrapped
     * and used to decrypt the saved tokens
     *
     * @return An ArrayList of Tokens
     */
    public String loadTokens() throws IOException, GeneralSecurityException {
        logprint("LOADING TOKEN");
        byte[] data = loadDataFromFile(DATAFILE);
        return new String(data);
    }

    public PublicKey getPIPubkey(String serial) throws GeneralSecurityException, IOException {
        if (baseFilePath == null) return null;
        return getPIPubkey(baseFilePath, serial);
    }

    PublicKey getPIPubkey(String filepath, String serial) throws GeneralSecurityException, IOException {
        byte[] keybytes = loadDataFromFile(serial + "_" + PUBKEYFILE, filepath);
        // build pubkey
        if (keybytes == null) return null;
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(keybytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(X509publicKey);
    }

    /**
     * Load the data from an encrypted file. The baseFilePath of Util will be used if set.
     * baseFilePath + "/" + fileName
     *
     * @param fileName Name of the file to load
     * @return raw data as byte array, null if no baseFilePath is set or there is no file
     */
    private byte[] loadDataFromFile(String fileName) throws IOException, GeneralSecurityException {
        if (baseFilePath == null) return null;
        return loadDataFromFile(fileName, baseFilePath);
    }

    /**
     * Load the data from an encrypted file, using the specified baseFilePath (from context).
     * baseFilePath + "/" + fileName
     *
     * @param fileName     Name of the file to load
     * @param baseFilePath baseFilePath of the Context
     * @return raw data as byte array, null if there is no file
     */
    private byte[] loadDataFromFile(String fileName, String baseFilePath) throws IOException, GeneralSecurityException {
        byte[] encryptedData = readFile(new File(baseFilePath + "/" + fileName));
        // decrypt
        SecretKey encryptionKey = getSecretKey(new File(baseFilePath + "/" + KEYFILE));
        if (encryptedData == null) {
            return null;
        }
        return decrypt(encryptionKey, encryptedData);
    }

    private byte[] readFile(File file) throws IOException {
        try (InputStream in = new FileInputStream(file)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int count;
            while ((count = in.read(buffer)) != -1) {
                bytes.write(buffer, 0, count);
            }
            return bytes.toByteArray();
        } catch (FileNotFoundException e) {
            logprint("File: " + file.getAbsolutePath() + " not found");
            return null;
        }
    }

    public String loadFirebaseConfig() throws IOException, GeneralSecurityException {
        byte[] data = loadDataFromFile(FB_CONFIG_FILE);
        if (data == null) return null;
        else return new String(data);
    }

    private static byte[] decrypt(SecretKey secretKey, GCMParameterSpec iv, byte[] cipherText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CRYPT_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return cipher.doFinal(cipherText);
    }

    static byte[] decrypt(SecretKey secretKey, byte[] cipherText)
            throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {
        //byte[] iv = Arrays.copyOfRange(cipherText, 0, IV_LENGTH);
        GCMParameterSpec params = new GCMParameterSpec(128, cipherText, 0, 12);
        byte[] cipher = Arrays.copyOfRange(cipherText, IV_LENGTH, cipherText.length);
        return decrypt(secretKey, params, cipher);
    }

    /**
     * Load our symmetric secret key.
     * The symmetric secret key is stored securely on disk by wrapping
     * it with a public/private key pair, possibly backed by hardware.
     */
    public SecretKey getSecretKey(File keyFile)
            throws GeneralSecurityException, IOException {
        if (secretKeyWrapper == null) {
            throw new GeneralSecurityException("No SecretKeyWrapper available!");
        }

//        // Generate secret key if none exists
//        if (!keyFile.exists()) {
//            final byte[] raw = new byte[KEY_LENGTH];
//            new SecureRandom().nextBytes(raw);
//            final SecretKey key = new SecretKeySpec(raw, "AES");
//            final byte[] wrapped = secretKeyWrapper.wrap(key);
//            writeFile(keyFile, wrapped);
//        }

        // Even if we just generated the key, always read it back to ensure we
        // can read it successfully.
        final byte[] wrapped = readFile(keyFile);
        if (wrapped == null) return null;
        return secretKeyWrapper.unwrap(wrapped);
    }

    /**
     * @param privateKey privateKey to sign the message with
     * @param message    message to sign
     * @return Base32 formatted signature
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static String sign(PrivateKey privateKey, String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] bMessage = message.getBytes(StandardCharsets.UTF_8);

        Signature s = Signature.getInstance(SIGNING_ALGORITHM);
        s.initSign(privateKey);
        s.update(bMessage);

        byte[] signature = s.sign();
        return new Base32().encodeAsString(signature);
    }

    /**
     * @param publicKey publicKey to verify the signature with
     * @param signature signature to verify, !!formatted in Base32!!
     * @param payload   payload that was signed
     * @return true if the signature is valid, false otherwise
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     */
    public static boolean verifySignature(PublicKey publicKey, String signature, String payload) throws InvalidKeyException,
            NoSuchAlgorithmException, SignatureException {
        if (!new Base32().isInAlphabet(signature)) {
            logprint("verifySignature: The given signature is not Base32 encoded!");
            return false;
        }

        byte[] message = payload.getBytes(StandardCharsets.UTF_8);
        byte[] bSignature = new Base32().decode(signature);
        Signature sig = Signature.getInstance(SIGNING_ALGORITHM);

        sig.initVerify(publicKey);
        sig.update(message);
        return sig.verify(bSignature);
    }

    public byte[] decodeBase64(String key) {
        return Base64.decode(key, Base64.DEFAULT);
    }

    public String encodeBase64(byte[] data) {
        return Base64.encodeToString(data, Base64.URL_SAFE);
    }

    /**
     * Converts a byte array to a Hex String
     *
     * @param ba byte array to convert
     * @return the Hex as String
     */
    public static String byteArrayToHexString(byte[] ba) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < ba.length; i++)
            str.append(String.format("%02x", ba[i]));
        return str.toString();
    }

    /**
     * Converts a Hex string to a byte array
     *
     * @param hex: the Hex string to convert
     * @return a byte array
     */
    public static byte[] hexStringToByteArray(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    public static void logprint(String msg) {
        if (msg == null) return;
        Log.e(TAG, msg);
    }

    public static String insertPeriodically(String text, int stepSize) {
        StringBuilder builder = new StringBuilder(text.length() + " ".length() * (text.length() / stepSize) + 1);
        int index = 0;
        String prefix = "";
        while (index < text.length()) {
            builder.append(prefix);
            prefix = " ";
            builder.append(text.substring(index,
                    Math.min(index + stepSize, text.length())));
            index += stepSize;
        }
        return builder.toString();
    }
}