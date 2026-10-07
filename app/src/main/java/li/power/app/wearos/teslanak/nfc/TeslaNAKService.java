package li.power.app.wearos.teslanak.nfc;

import android.app.KeyguardManager;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.os.SystemClock;

import android.widget.Toast;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;

/*
 *
 * Ref: https://gist.github.com/darconeous/2cd2de11148e3a75685940158bddf933
 *
 * */
public class TeslaNAKService extends HostApduService {
    /* Card commands we support. */
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x04;
    private static final byte INS_AUTHENTICATE = (byte) 0x11;
    private static final byte INS_GET_CARD_INFO = (byte) 0x14;

    private static final byte[] SW_SUCCESS = new byte[]{(byte) 0x90, 0x00};
    private static final byte[] SW_CLA_NOT_SUPPORTED = new byte[]{(byte) 0x6E, (byte) 0x00};
    private static final byte[] SW_INS_NOT_SUPPORTED = new byte[]{(byte) 0x6D, (byte) 0x00};
    private static final byte[] SW_UNKNOWN = new byte[]{(byte) 0x6F, (byte) 0x00};
    private static final byte[] SW_WRONG_LENGTH = new byte[]{(byte) 0x67, (byte) 0x00};
    private static final byte[] SW_CONDITIONS_NOT_SATISFIED = new byte[]{(byte) 0x69, (byte) 0x85};

    public static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    /* EC P-256 key generated inside Android Keystore; the private key never leaves secure hardware. */
    public static final String KEY_ALIAS = "tesla_nak_ec";
    private static final String CURVE = "secp256r1";

    /* How long the key keeps answering readers after the app leaves the foreground. */
    public static final long ARM_WINDOW_MS = 30_000;

    private static volatile boolean sForeground;
    private static volatile long sArmedUntil;

    private KeyStore keyStore;

    /*
     * The card only answers while the app is open, or for ARM_WINDOW_MS after it was left,
     * so an unattended watch does not respond to arbitrary (or relayed) NFC readers.
     */
    public static void setForeground(boolean foreground) {
        sForeground = foreground;
        if (!foreground) {
            sArmedUntil = SystemClock.elapsedRealtime() + ARM_WINDOW_MS;
        }
    }

    private static boolean isArmed() {
        return sForeground || SystemClock.elapsedRealtime() < sArmedUntil;
    }

    @Override
    public void onCreate() {
        setupBouncyCastle();
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (!keyStore.containsAlias(KEY_ALIAS)) {
                Toast.makeText(this, "Please open app to generate the keypair", Toast.LENGTH_LONG).show();
            }

        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Toast.makeText(this, "Error initializing keystore", Toast.LENGTH_LONG).show();
            e.printStackTrace();
        }

        super.onCreate();
    }

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {

        if (!isArmed() || !isWatchUnlocked()) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }

        return process(commandApdu);
    }

    /* Requires a secure lock screen to be set up, and the watch to currently be unlocked. */
    private boolean isWatchUnlocked() {

        KeyguardManager km = getSystemService(KeyguardManager.class);

        return km != null && km.isDeviceSecure() && !km.isDeviceLocked();
    }

    private byte[] process(byte[] commandApdu) {

        CommandAPDU apdu = new CommandAPDU(commandApdu);
        if (apdu.getCLA() == 0x00 && apdu.getINS() == 0xa4 && apdu.getP1() == 0x04 && apdu.getP2() == 0x00) {
            return SW_SUCCESS;
        }

        if ((apdu.getCLA() & 0x80) != 0x80) {
            return SW_CLA_NOT_SUPPORTED;
        }

        switch (apdu.getINS()) {
            case INS_GET_PUBLIC_KEY:
                return processGetPublicKey();
            case INS_AUTHENTICATE:
                return processAuthenticate(apdu.getData());
            case INS_GET_CARD_INFO:
                return processGetCardInfo();
            default:
                return SW_INS_NOT_SUPPORTED;
        }
    }

    private byte[] processGetCardInfo() {
        return new byte[]{0x00, 0x01, (byte) 0x90, 0x00};
    }

    /* Decodes and validates (on-curve check) an uncompressed P-256 point sent by the reader. */
    public static PublicKey loadPublicKey(byte[] data) throws Exception {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(CURVE);
        ECPublicKeySpec pubKey = new ECPublicKeySpec(
                params.getCurve().decodePoint(data), params);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(pubKey);
    }

    private static byte[] encodeUncompressed(java.security.spec.ECPoint w) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        copyUnsigned32(w.getAffineX(), out, 1);
        copyUnsigned32(w.getAffineY(), out, 33);
        return out;
    }

    private static void copyUnsigned32(BigInteger v, byte[] out, int offset) {
        byte[] b = v.toByteArray();
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, offset + 32 - len, len);
    }

    private byte[] processGetPublicKey() {
        try {

            ECPublicKey pubKey = (ECPublicKey) keyStore.getCertificate(KEY_ALIAS).getPublicKey();

            byte[] resp = new byte[67];
            System.arraycopy(encodeUncompressed(pubKey.getW()), 0, resp, 0, 65);
            resp[65] = (byte) 0x90;
            resp[66] = 0x00;

            return resp;
        } catch (Exception e) {
            e.printStackTrace();
            return SW_UNKNOWN;
        }

    }

    private byte[] processAuthenticate(byte[] buffer) {
        if (buffer.length < 0x51) {
            return SW_WRONG_LENGTH;
        }

        byte[] pubKey = new byte[65];
        System.arraycopy(buffer, 0, pubKey, 0, 65);
        byte[] challenge = new byte[16];
        byte[] salt = new byte[4];
        new SecureRandom().nextBytes(salt);
        System.arraycopy(salt, 0, challenge, 0, 4);
        System.arraycopy(buffer, 69, challenge, 4, 12);
        try {
            byte[] resp = new byte[18];
            System.arraycopy(doAuthenticate(pubKey, challenge), 0, resp, 0, 16);
            resp[16] = (byte) 0x90;
            resp[17] = 0x00;
            return resp;
        } catch (Exception e) {
            e.printStackTrace();
            return SW_UNKNOWN;
        }
    }


    /* ECDH runs inside Android Keystore; only the shared secret is returned to the app. */
    private byte[] doECDH(byte[] pubKey) throws Exception {
        PrivateKey privKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", KEYSTORE_PROVIDER);
        ka.init(privKey);
        ka.doPhase(loadPublicKey(pubKey), true);
        return ka.generateSecret();
    }

    private byte[] getEncryptKey(byte[] pubKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        digest.update(doECDH(pubKey));
        byte[] key = new byte[16];
        System.arraycopy(digest.digest(), 0, key, 0, 16);
        return key;
    }

    private byte[] doAuthenticate(byte[] pubKey, byte[] challenge) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(getEncryptKey(pubKey), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(challenge);

    }

    private void setupBouncyCastle() {
        final Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            return;
        }
        if (provider.getClass().equals(BouncyCastleProvider.class)) {
            return;
        }
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    @Override
    public void onDeactivated(int reason) {

    }
}
