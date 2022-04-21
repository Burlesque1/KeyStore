package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.os.Build;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import android.os.Message;
import android.security.*;
import android.security.identity.*;
import android.security.keystore.*;

import android.util.Log;



public class MainActivity extends AppCompatActivity {

    protected double kk(){
        Log.w("TAG","DSFFSDF");
//        PersonalizationData.Builder();
//        WritableIdentityCredential
//        IdentityCredential();
        System.out.println(IdentityCredentialStore.CIPHERSUITE_ECDHE_HKDF_ECDSA_WITH_AES_256_GCM_SHA256);

        AccessControlProfileId acpId = new AccessControlProfileId(11);
        AccessControlProfile acP = new AccessControlProfile.Builder(acpId).build();
        System.out.println(acP);
        PersonalizationData.Builder pdb = new PersonalizationData.Builder();
        pdb.addAccessControlProfile(acP);
        PersonalizationData pd = pdb.build();

        Salary s = new Salary("123","dsfdsf",123,12.3);
//        IdentityCredentialStore.getInstance();
        store ss = new store();
//        System.out.println(s);
//        System.out.println(ss);

        return 3.333;

    }

    protected void key() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException {
        // generate AES key
        Context context = getApplicationContext();
//        MasterKey mainKey = new MasterKey.Builder(context)
//                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
//                .build();

        // generate new private key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(new KeyGenParameterSpec.Builder(
                "alias",
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                .build());

        KeyPair kp = kpg.generateKeyPair();

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry("alias", null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w("TAG", "Not an instance of a PrivateKeyEntry");
        } else {
            Log.w("TAG", "an instance of a PrivateKeyEntry");
        }


        Enumeration<String> aliases = ks.aliases();
        System.out.println(aliases);

        X509Certificate csr;


        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());

    }

    void sign() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry("alias", null);
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
    }
    private void startSendHttpRequestThread(final String reqUrl)
    {
        Thread sendHttpRequestThread = new Thread()
        {
            @Override
            public void run() {
                // Maintain http url connection.
                HttpURLConnection httpConn = null;

                // Read text input stream.
                InputStreamReader isReader = null;

                // Read text into buffer.
                BufferedReader bufReader = null;

                // Save server response text.
                StringBuffer readTextBuf = new StringBuffer();

                try {
                    // Create a URL object use page url.
                    URL url = new URL(reqUrl);

                    // Open http connection to web server.
                    httpConn = (HttpURLConnection)url.openConnection();

                    // Set http request method to get.
                    httpConn.setRequestMethod("POST");
                    httpConn.setRequestProperty("Content-Type", "application/json; utf-8");
                    httpConn.setRequestProperty("Accept", "application/json");
                    httpConn.setDoOutput(true);

                    // Set connection timeout and read timeout value.
                    httpConn.setConnectTimeout(10000);
                    httpConn.setReadTimeout(10000);

                    /*
                    "curl -X POST
                    http://pico-license-device-boe.byted.org/device/license/active/v1
                    -d {\"active_method\":2,\"device_sn\":\"PA7910DGD8260009D\"}
                    -H Content-Type:application/json";
                     */

//                    String jsonInputString = "{\"name\": \"Upendra\", \"job\": \"Programmer\"}";
                    String jsonInputString = "{\"active_method\": 2, \"device_sn\": \"PA7910DGD8260009D\"}";

                    try(OutputStream os = httpConn.getOutputStream()) {
                        byte[] input = jsonInputString.getBytes("utf-8");
                        os.write(input, 0, input.length);
                    }

                    // Get input stream from web url connection.
                    InputStream inputStream = httpConn.getInputStream();

                    // Create input stream reader based on url connection input stream.
                    isReader = new InputStreamReader(inputStream);

                    // Create buffered reader.
                    bufReader = new BufferedReader(isReader);

                    // Read line of text from server response.
                    String line = bufReader.readLine();

                    // Loop while return line is not null.
                    while(line != null)
                    {
                        // Append the text to string buffer.
                        readTextBuf.append(line);

                        // Continue to read text line.
                        line = bufReader.readLine();
                    }

                    System.out.println(readTextBuf.toString());

                }catch(MalformedURLException ex)
                {

                }catch(IOException ex)
                {

                }finally {
                    try {
                        if (bufReader != null) {
                            bufReader.close();
                            bufReader = null;
                        }

                        if (isReader != null) {
                            isReader.close();
                            isReader = null;
                        }

                        if (httpConn != null) {
                            httpConn.disconnect();
                            httpConn = null;
                        }
                    }catch (IOException ex)
                    {

                    }
                }
            }
        };
        // Start the child thread to request web page.
        sendHttpRequestThread.start();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

//        URL url = new URL("http://www.yahoo.com");
        startSendHttpRequestThread("http://pico-license-device-boe.byted.org/device/license/active/v1");



        Log.d("TAG", String.format("%s - %s - %s - %s - %s", Build.BRAND, Build.DEVICE, Build.PRODUCT, Build.MANUFACTURER, Build.MODEL));

//        try {
////            Salary s = new Salary("Mohd Mohtashim", "Ambehta, UP", 3, 3600.00);
////            System.out.println("Call mailCheck using Salary reference --");
////            s.mailCheck();
//
//            key();
//            kk();
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (InvalidKeyException e) {
//            e.printStackTrace();
//        } catch (NoSuchProviderException e) {
//            e.printStackTrace();
//        } catch (InvalidAlgorithmParameterException e) {
//            e.printStackTrace();
//        } catch (UnrecoverableEntryException e) {
//            e.printStackTrace();
//        }
    }


    private class MasterKey {
    }
}