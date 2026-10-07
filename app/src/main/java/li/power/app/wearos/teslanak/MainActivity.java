package li.power.app.wearos.teslanak;

import android.app.Activity;
import android.app.KeyguardManager;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.widget.TextView;
import androidx.core.splashscreen.SplashScreen;
import li.power.app.wearos.teslanak.databinding.ActivityMainBinding;
import li.power.app.wearos.teslanak.nfc.TeslaNAKService;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

public class MainActivity extends Activity {

    /* Keystore alias and preferences file used by versions <= 1.4.2 (software EC key wrapped by RSA). */
    private static final String LEGACY_KEY_ALIAS = "tesla_nak";

    private TextView mTextView;
    private boolean ready;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        SplashScreen.installSplashScreen(this);
        super.onCreate(savedInstanceState);

        ActivityMainBinding binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        mTextView = binding.text;
    }

    @Override
    protected void onResume() {
        super.onResume();
        ready = prepareKey();
        if (ready) {
            TeslaNAKService.setForeground(true);
        }
    }

    @Override
    protected void onPause() {
        if (ready) {
            TeslaNAKService.setForeground(false);
        }
        super.onPause();
    }

    private boolean prepareKey() {
        KeyguardManager km = getSystemService(KeyguardManager.class);
        if (km == null || !km.isDeviceSecure()) {
            mTextView.setText(R.string.screenLockRequired);
            return false;
        }

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(TeslaNAKService.KEYSTORE_PROVIDER);
            keyStore.load(null);
            removeLegacyKey(keyStore);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            mTextView.setText(R.string.keystoreFailed);
            e.printStackTrace();
            return false;
        }

        try {
            if (!keyStore.containsAlias(TeslaNAKService.KEY_ALIAS)) {
                generateKey();
            }
        } catch (GeneralSecurityException | ProviderException e) {
            mTextView.setText(R.string.keypairFailed);
            e.printStackTrace();
            return false;
        }

        mTextView.setText(R.string.launched);
        return true;
    }

    private void removeLegacyKey(KeyStore keyStore) throws KeyStoreException {
        if (keyStore.containsAlias(LEGACY_KEY_ALIAS)) {
            keyStore.deleteEntry(LEGACY_KEY_ALIAS);
        }
        deleteSharedPreferences(LEGACY_KEY_ALIAS);
    }

    private void generateKey() throws GeneralSecurityException {
        try {
            generateKey(true);
        } catch (StrongBoxUnavailableException e) {
            generateKey(false);
        }
    }

    private void generateKey(boolean strongBox) throws GeneralSecurityException {
        KeyGenParameterSpec spec = new KeyGenParameterSpec
                .Builder(TeslaNAKService.KEY_ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setUnlockedDeviceRequired(true)
                .setIsStrongBoxBacked(strongBox)
                .build();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_EC, TeslaNAKService.KEYSTORE_PROVIDER);
        keyPairGenerator.initialize(spec);
        keyPairGenerator.generateKeyPair();
    }

}
