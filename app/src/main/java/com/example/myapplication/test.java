package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

public class test extends AppCompatActivity {

    protected KeyPair generateAAAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        // Create KeyPairGenerator and set generation parameters for an ECDSA key pair
        // using the NIST P-256 curve.  "Key1" is the key alias.
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder("Key1", KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256,
                                KeyProperties.DIGEST_SHA384,
                                KeyProperties.DIGEST_SHA512)
                        // Only permit the private key to be used if the user
                        // authenticated within the last five minutes.
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationValidityDurationSeconds(5 * 60)
                        // Request an attestation with challenge "hello world".
                        .setAttestationChallenge("hello world".getBytes("UTF-8"))
                        .build());
        // Generate the key pair. This will result in calls to both generate_key() and
        // attest_key() at the keymaster2 HAL.
        return  keyPairGenerator.generateKeyPair();
    }

    protected KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        /*
         * Generate a new EC key pair entry in the Android Keystore by
         * using the KeyPairGenerator API. The private key can only be
         * used for signing or verification and only with SHA-256 or
         * SHA-512 as the message digest.
         */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        kpg.initialize(new KeyGenParameterSpec.Builder(
                "alias",
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                .build());

        return kpg.generateKeyPair();
    }

    protected KeyPair generateECKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        /*
         * Generate a new EC key pair entry in the Android Keystore by
         * using the KeyPairGenerator API. The private key can only be
         * used for signing or verification and only with SHA-256 or
         * SHA-512 as the message digest.
         */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(new KeyGenParameterSpec.Builder(
                "alias",
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                .build());

        return kpg.generateKeyPair();
    }

    protected KeyPair generateKeyPair(String provider, String alias, String algorithm, int purpose) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                algorithm, provider);
        kpg.initialize(new KeyGenParameterSpec.Builder(
                alias,
                purpose)
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                .build());
//        Context context;
        return kpg.generateKeyPair();
    }

    protected void attestKey(KeyPair kp, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException  {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Certificate[] certs = keyStore.getCertificateChain(alias);
        // certs[0] is the attestation certificate. certs[1] signs certs[0], etc.,
        // up to certs[certs.length - 1].
        Log.d("TAG", String.valueOf(certs.length));

        for(Certificate cert:certs) {
//            System.out.println(cert.toString());
            Log.d("TAG",cert.getType());
        }
    }

    byte[] sign(byte[] data) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry("alias", null);
//        Log.d("TAG",entry.toString());
//        Log.d("TAG",((KeyStore.PrivateKeyEntry) entry).getPrivateKey().toString());

        PrivateKey pk = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        Log.w("TAG",pk.getAlgorithm());
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(pk);
        s.update(data);
        return s.sign();
    }

    boolean verify(byte[] data, byte[] signature) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry("alias", null);

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w("TAG", "Not an instance of a PrivateKeyEntry");
            return false;
        }
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
        s.update(data);
        return s.verify(signature);
    }

    void listEntries() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        /*
         * Load the Android KeyStore instance using the
         * "AndroidKeyStore" provider to list out what entries are
         * currently stored.
         */
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements()){
            System.out.println(aliases.nextElement());
        }
        System.out.println("end");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            listEntries();
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            KeyPair kp = generateECKeyPair();
            PrivateKey prikey = kp.getPrivate();
            KeyFactory factory = KeyFactory.getInstance(prikey.getAlgorithm(), "AndroidKeyStore");

            KeyInfo keyInfo = factory.getKeySpec(prikey, KeyInfo.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                Log.d("TAG", String.valueOf(keyInfo.getSecurityLevel()));
            }
            else{
                Log.d("fasdfsaf", String.valueOf(keyInfo.isInsideSecureHardware()));
            }
//

            Log.d("TAG",kp.getPrivate().getAlgorithm());
            Log.d("TAG",kp.getPublic().getAlgorithm());

            attestKey(kp, "alias");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        try {
            byte[] s = "hello world".getBytes(StandardCharsets.UTF_8);
            byte[] res = sign(s);
            Log.w("TAG", String.valueOf(res));

            Log.w("TAG", String.valueOf(verify(s, res)));
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | InvalidKeyException | SignatureException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }

//        try {
//            KeyPair kp = generateECKeyPair();
//            keyAttestation(kp);
//            Log.d("TAG","gsdgsfdgasfdgasdf");
//        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | CertificateException | KeyStoreException | IOException e) {
//            e.printStackTrace();
//        }
    }
}