package org.kivy.utils;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class AssetExtractor {

    private static final String TAG = "AssetExtractor";

    // Decrypt and extract ZIP
    public static void decryptAndExtractZip(Context context, String assetPath, String outputPath, String password) {
        Log.i(TAG, "Starting extraction of asset: " + assetPath);
        AssetManager assetManager = context.getAssets();

        try (InputStream encryptedInput = assetManager.open(assetPath);
             InputStream zipStream = decryptAES(encryptedInput, password)) {

            unzip(zipStream, new File(outputPath));
            Log.i(TAG, "Decryption and extraction completed: " + outputPath);

        } catch (FileNotFoundException fnfe) {
            Log.e(TAG, "Asset not found: " + assetPath, fnfe);
        } catch (SecurityException se) {
            Log.e(TAG, "SecurityException (maybe incorrect password): ", se);
        } catch (IOException ioe) {
            Log.e(TAG, "I/O error during extraction", ioe);
        } catch (Exception e) {
            Log.e(TAG, "Unexpected error during decryptAndExtractZip", e);
        }
    }

    // New: Just extract a plain ZIP from assets (no encryption)
    public static void extractZipFromAssets(Context context, String assetPath, String outputPath) {
        Log.i(TAG, "Extracting plain zip from assets: " + assetPath);
        AssetManager assetManager = context.getAssets();

        try (InputStream zipInput = assetManager.open(assetPath)) {
            unzip(zipInput, new File(outputPath));
            Log.i(TAG, "Extraction completed: " + outputPath);
        } catch (FileNotFoundException fnfe) {
            Log.e(TAG, "Asset not found: " + assetPath, fnfe);
        } catch (IOException ioe) {
            Log.e(TAG, "I/O error during zip extraction", ioe);
        } catch (Exception e) {
            Log.e(TAG, "Unexpected error during extractZipFromAssets", e);
        }
    }

    // Decrypt stream using AES-CBC (IV from first 16 bytes)
    private static InputStream decryptAES(InputStream encryptedStream, String password) throws Exception {
        Log.i(TAG, "Decrypting AES...");

        byte[] iv = new byte[16];
        int readBytes = encryptedStream.read(iv);
        if (readBytes != 16) {
            throw new IOException("Failed to read IV from encrypted stream");
        }
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] key = digest.digest(password.getBytes("UTF-8"));
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        return new CipherInputStream(encryptedStream, cipher);
    }

    // Unzip content to targetDir
    private static void unzip(InputStream zipInputStream, File targetDir) throws IOException {
        Log.i(TAG, "Unzipping to: " + targetDir.getAbsolutePath());

        if (!targetDir.exists() && !targetDir.mkdirs()) {
            throw new IOException("Failed to create target directory: " + targetDir.getAbsolutePath());
        }

        try (ZipInputStream zis = new ZipInputStream(zipInputStream)) {
            ZipEntry entry;
            byte[] buffer = new byte[4096];
            boolean foundEntries = false;

            while ((entry = zis.getNextEntry()) != null) {
                foundEntries = true;
                File outFile = new File(targetDir, entry.getName());
                Log.i(TAG, "Extracting: " + outFile.getAbsolutePath());

                if (entry.isDirectory()) {
                    if (!outFile.exists() && !outFile.mkdirs()) {
                        throw new IOException("Failed to create directory: " + outFile.getAbsolutePath());
                    }
                } else {
                    File parent = outFile.getParentFile();
                    if (!parent.exists() && !parent.mkdirs()) {
                        throw new IOException("Failed to create directory: " + parent.getAbsolutePath());
                    }

                    try (FileOutputStream fos = new FileOutputStream(outFile)) {
                        int len;
                        while ((len = zis.read(buffer)) != -1) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
                zis.closeEntry();
            }

            if (!foundEntries) {
                Log.w(TAG, "No entries found in zip file. Possibly corrupted or empty.");
            }
        }

        Log.i(TAG, "Unzip complete.");
    }
}

