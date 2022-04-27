package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.os.Build;


import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.Charset;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import android.security.keystore.*;

import android.util.Log;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.json.JSONException;
import org.json.JSONObject;


public class MainActivity extends AppCompatActivity {

    Certificate cert;

    protected void RSAKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException {
        // generate AES key
        Context context = getApplicationContext();
//        MasterKey mainKey = new MasterKey.Builder(context)
//                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
//                .build();

        // generate new private key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

        kpg.initialize(new KeyGenParameterSpec.Builder(
                "alias",
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                .build());

        KeyPair kp = kpg.generateKeyPair();
        Log.d("TAG", String.valueOf(kp.getPrivate().toString()));

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");

        ks.load(null);
        KeyStore.Entry entry = ks.getEntry("alias", null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w("TAG", "Not an instance of a PrivateKeyEntry");
        } else {
            Log.w("TAG", "an instance of a PrivateKeyEntry");
        }
    }

    void sign() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry("alias", null);
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
    }

    Certificate extractCert(String readText) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {

        String certString = readText.substring(readText.indexOf("-----BEGIN CERTIFICATE-----"),readText.indexOf(",\"base_resp\""));
        certString = certString.replace("\\n", "\n");
        Log.d(" certstring", certString);

        InputStream is = new ByteArrayInputStream(certString.getBytes(Charset.defaultCharset()));
        BufferedInputStream bis = new BufferedInputStream(is);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(bis);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null);
        ks.setCertificateEntry("test", cert);

        System.out.println(ks.isCertificateEntry("test"));
        Certificate test = ks.getCertificate("test");
        Log.d("pubkey", String.valueOf(test.getPublicKey()));

        return cert;
    }

    BufferedInputStream extractCertString(String readText) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {

        String certString = readText.substring(readText.indexOf("-----BEGIN CERTIFICATE-----"),readText.indexOf(",\"base_resp\""));
        certString = certString.replace("\\n", "\n");

        InputStream is = new ByteArrayInputStream(certString.getBytes(Charset.defaultCharset()));
        BufferedInputStream bis = new BufferedInputStream(is);

        return bis;
    }

    private void startSendHttpRequestThread(final String reqUrl, final String inputString) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {
        // Save server response text.
        StringBuffer readTextBuf = new StringBuffer();

        final String res;
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


                    try(OutputStream os = httpConn.getOutputStream()) {
                        byte[] input = inputString.getBytes();
                        os.write(input, 0, input.length);
                    }


                    // Get input stream from web url connection.
                    InputStream inputStream;
                    int status = httpConn.getResponseCode();
                    if (status != HttpURLConnection.HTTP_OK)  {
                        Log.w("ResponseCode", String.valueOf(status));
                        inputStream = httpConn.getErrorStream();
                    }
                    else  {
                        inputStream = httpConn.getInputStream();
                    }


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

                    String res = readTextBuf.toString();
                    Log.d("res",res);
                    Certificate cert = extractCert(res);
//                    BufferedInputStream bis = extractCertString(res);

                } catch (ProtocolException e) {
                    e.printStackTrace();
                } catch (MalformedURLException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (CertificateException e) {
                    e.printStackTrace();
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } finally {
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
                        ex.printStackTrace();
                    }
                }
            }
        };
        // Start the child thread to request web page.
        sendHttpRequestThread.start();
    }

    private String startSendHttpRequestThread(final String reqUrl, final JSONObject payload) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {
        // Save server response text.
        StringBuffer readTextBuf = new StringBuffer();

        final String res;
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


                    try(OutputStream os = httpConn.getOutputStream()) {
                        byte[] input = payload.toString().getBytes();
                        os.write(input, 0, input.length);
                    }


                    // Get input stream from web url connection.
                    InputStream inputStream;
                    int status = httpConn.getResponseCode();
                    if (status != HttpURLConnection.HTTP_OK)  {
                        Log.w("ResponseCode", String.valueOf(status));
                        inputStream = httpConn.getErrorStream();
                    }
                    else  {
                        inputStream = httpConn.getInputStream();
                    }


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

                    String res = readTextBuf.toString();
                    Log.d("res",res);
                    Certificate cert = extractCert(res);

                    X509Certificate x = (X509Certificate) cert;
                    Log.w("x", x.getSigAlgName());
                    Log.w("x", String.valueOf(x.getIssuerDN()));
                    Log.w("x", String.valueOf(x.getSubjectDN()));

                } catch (ProtocolException e) {
                    e.printStackTrace();
                } catch (MalformedURLException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (CertificateException e) {
                    e.printStackTrace();
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } finally {
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
                        ex.printStackTrace();
                    }
                }
            }
        };
        // Start the child thread to request web page.
        sendHttpRequestThread.start();


        return readTextBuf.toString();
    }

    protected PKCS10CertificationRequest test() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, OperatorCreationException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"); // store the key in the Android KeyStore for security purposes
        keyGen.initialize(new KeyGenParameterSpec.Builder(
                "key1",
                KeyProperties.PURPOSE_SIGN)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)
                .build()); // defaults to RSA 2048
        KeyPair keyPair = keyGen.generateKeyPair();

        String CN_PATTERN = "CN=%s, OU=%s, O=%s, C=%s";

        String principal = String.format(CN_PATTERN, "commonName", "organizationUnit", "organization", "country");

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WITHRSA").build(keyPair.getPrivate());

        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(principal), keyPair.getPublic());
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(
                true));
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                extensionsGenerator.generate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);
        return csr;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Log.d("TAG", String.format("%s - %s - %s - %s - %s", Build.BRAND, Build.DEVICE, Build.PRODUCT, Build.MANUFACTURER, Build.MODEL));


//        String url = "http://pico-license-device-boe.byted.org/device/license/active/v1";
//        String jsonInputString = "{\"active_method\": 2, \"device_sn\": \"PA7910DGD8260009D\"}";
        String url = "http://pico-license-device-boe.byted.org/device/license/deep/v1";
        String jsonInputString = "{\"csr\": \"-----BEGIN CERTIFICATE-----\\nMIIBWzCBxQIBADAcMRowGAYDVQQDExFQQTc5MTBER0Q4MjYwMDA5RDCBnzANBgkq\\nhkiG9w0BAQEFAAOBjQAwgYkCgYEAwp3PMQ9VPvbINXohLpi+L82aNn6BsIxu8Ew6\\nrXlFUtgDXNHxc0/p3aNxN1pFBSXn5bH8Y+ADW7A/1VSOmQiCg0wD8xp5JHYoOPPe\\nSDea64mEVek/A42b3jFie5ImjDX8HCBq9p4Bznft0sklvMjDEMHKb1V3rRoj2AHS\\nvJKsPoECAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4GBALozPEue0ZVyRpK1iTquF3A2\\nRGqJ76hop3/3BeGqnI+fKlQfWeZ0dxnHXJ6C6I7fK9cJPmdL3oLowMxZXufdOY5P\\nB4icU7KtL1isdMQz0jT/SlD0TWG1mZFm/bZGFW7jPZd6Xx8ZkXrB9WJOjPkRj91s\\nWUOmzLCTZBd57o2vu+TA\\n-----END CERTIFICATE-----\", \"device_sn\" : \"PA7910DGD8260009D\"}";
//        String jsonInputString = "{\"csr\": \"-----BEGIN CERTIFICATE-----\nMIIBWzCBxQIBADAcMRowGAYDVQQDExFQQTc5MTBER0Q4MjYwMDA5RDCBnzANBgkq\nhkiG9w0BAQEFAAOBjQAwgYkCgYEAwp3PMQ9VPvbINXohLpi+L82aNn6BsIxu8Ew6\nrXlFUtgDXNHxc0/p3aNxN1pFBSXn5bH8Y+ADW7A/1VSOmQiCg0wD8xp5JHYoOPPe\nSDea64mEVek/A42b3jFie5ImjDX8HCBq9p4Bznft0sklvMjDEMHKb1V3rRoj2AHS\nvJKsPoECAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4GBALozPEue0ZVyRpK1iTquF3A2\nRGqJ76hop3/3BeGqnI+fKlQfWeZ0dxnHXJ6C6I7fK9cJPmdL3oLowMxZXufdOY5P\nB4icU7KtL1isdMQz0jT/SlD0TWG1mZFm/bZGFW7jPZd6Xx8ZkXrB9WJOjPkRj91s\nWUOmzLCTZBd57o2vu+TA\n-----END CERTIFICATE-----\", \"device_sn\" : \"PA7910DGD8260009D\"}";

        /*
            {
              "ca": 0,
              "ca_url": true,
              "crl": true,
              "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
              "not_after": "2026-01-02T15:04:05Z",
              "ocsp": true,
              "parent_certificate_id": 1864,
              "private_key": "",
              "record": true
            }
         */
        Log.w("inputstring",jsonInputString);

        try {

            PKCS10CertificationRequest csr = test();
            PemObject pemObject = new PemObject("CERTIFICATE",csr.getEncoded());
            StringWriter stringWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(stringWriter);
            pemWriter.writeObject(pemObject);
            pemWriter.close();
            stringWriter.close();
            Log.w("pemcsr",stringWriter.toString());

            JSONObject jsonObject = new JSONObject();
            jsonObject.put("csr","-----BEGIN CERTIFICATE-----\nMIIBWzCBxQIBADAcMRowGAYDVQQDExFQQTc5MTBER0Q4MjYwMDA5RDCBnzANBgkq\nhkiG9w0BAQEFAAOBjQAwgYkCgYEAwp3PMQ9VPvbINXohLpi+L82aNn6BsIxu8Ew6\nrXlFUtgDXNHxc0/p3aNxN1pFBSXn5bH8Y+ADW7A/1VSOmQiCg0wD8xp5JHYoOPPe\nSDea64mEVek/A42b3jFie5ImjDX8HCBq9p4Bznft0sklvMjDEMHKb1V3rRoj2AHS\nvJKsPoECAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4GBALozPEue0ZVyRpK1iTquF3A2\nRGqJ76hop3/3BeGqnI+fKlQfWeZ0dxnHXJ6C6I7fK9cJPmdL3oLowMxZXufdOY5P\nB4icU7KtL1isdMQz0jT/SlD0TWG1mZFm/bZGFW7jPZd6Xx8ZkXrB9WJOjPkRj91s\nWUOmzLCTZBd57o2vu+TA\n-----END CERTIFICATE-----");
            jsonObject.put("device_sn","PA7910DGD8260009D");
            Log.i("JSON", jsonObject.toString());


//            startSendHttpRequestThread(url, jsonInputString);
            startSendHttpRequestThread(url, jsonObject);

//            Certificate cert = extractCert(res);
//
//            PublicKey pk = cert.getPublicKey();
////                    cert.verify(pk);
//            KeyFactory factory = KeyFactory.getInstance(pk.getAlgorithm(), "AndroidKeyStore");
//            KeyInfo keyInfo;
////                    keyInfo = (KeyInfo)factory.getKeySpec(pk,KeyInfo.class);
//
//            System.out.println(pk.getAlgorithm());
//            System.out.println(cert.toString());
//
//            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
//            ks.load(null);
//            ks.setCertificateEntry("certAlias", cert);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (JSONException e) {
            e.printStackTrace();
        }

//        try {
//            RSAKey();
//            createWrappedKey();
//        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | InvalidKeyException | NoSuchProviderException | InvalidAlgorithmParameterException | UnrecoverableEntryException e) {
//            e.printStackTrace();
//        }
    }

}