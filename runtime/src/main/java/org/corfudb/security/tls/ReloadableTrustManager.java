package org.corfudb.security.tls;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import lombok.extern.slf4j.Slf4j;

/**
 * This trust manager reloads the trust store upon certificate verification failure.
 *
 * Created by zjohnny on 9/18/17.
 */
@Slf4j
public class ReloadableTrustManager implements X509TrustManager {
    private String trustStorePath, trustPasswordPath;
    private X509TrustManager trustManager;

    /**
     * Constructor.
     *
     * @param trustStorePath
     *          Location of trust store.
     * @param trustPasswordPath
     *          Location of trust store password.
     * @throws SSLException
     *          Thrown when there's an issue with loading the trust store.
     */
    public ReloadableTrustManager(String trustStorePath, String trustPasswordPath) throws SSLException {
        this.trustStorePath = trustStorePath;
        this.trustPasswordPath = trustPasswordPath;
        reloadTrustStore();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        reloadTrustStoreWrapper();
        trustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        reloadTrustStoreWrapper();
        trustManager.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    /**
     * Just a wrapper due to IDE pointing out duplicate code.
     *
     * @throws CertificateException
     *          Wrapper for any exception from reloading the trust store.
     */
    private void reloadTrustStoreWrapper() throws CertificateException {
        try {
            reloadTrustStore();
        } catch (SSLException e) {
            String message = "Unable to reload trust store " + trustStorePath + ".";
            log.error(message, e);
            throw new CertificateException(message, e);
        }
    }

    /**
     * Reload the trust manager.
     *
     * @throws SSLException
     *          Thrown when there's an issue with loading the trust store.
     */
    private void reloadTrustStore() throws SSLException {
        File trustFile = new File(trustStorePath);
        if (!trustFile.exists()) {
            String errorMessage = "Trust store file {" + trustStorePath + "} doesn't exist.";
            log.error(errorMessage);
            throw new SSLException(errorMessage);
        }

        String password = "";
        if (trustPasswordPath != null) {
            try {
                password = (new String(Files.readAllBytes(Paths.get(trustPasswordPath)))).trim();
            } catch (IOException e) {
                String errorMessage = "Unable to read trust store password file " + trustPasswordPath + ".";
                log.error(errorMessage, e);
                throw new SSLException(errorMessage, e);
            }
        }

        KeyStore trustStore;
        try {
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            String errorMessage = "Unable to initialize key store of type " + KeyStore.getDefaultType() + ".";
            log.error(errorMessage, e);
            throw new SSLException(errorMessage, e);
        }

        try {
            trustStore.load(new FileInputStream(trustStorePath), password.toCharArray());
        } catch (IOException e) {
            String errorMessage = "Unable to read trust store file " + trustStorePath + ".";
            log.error(errorMessage, e);
            throw new SSLException(errorMessage, e);
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = "No support for algorithm indicated in the trust store " + trustStorePath + ".";
            log.error(errorMessage, e);
            throw new SSLException(errorMessage, e);
        } catch (CertificateException e) {
            String errorMessage = "Unable to read certificate in trust store file " + trustStorePath + ".";
            log.error(errorMessage, e);
            throw new SSLException(errorMessage, e);
        }


        TrustManagerFactory tmf;
        try {
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = "No support for TrustManagerFactory default algorithm "
                    + TrustManagerFactory.getDefaultAlgorithm() + ".";
            log.error(errorMessage, e);
            throw new SSLException(errorMessage, e);
        }

        try {
            tmf.init(trustStore);
        } catch (KeyStoreException e) {
            String errorMessage = "Unable to load trust store " + trustStorePath + ".";
            log.error(errorMessage, e);
            throw new SSLException(errorMessage, e);
        }

        for (TrustManager tm: tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                trustManager = (X509TrustManager)tm;
                return;
            }
        }

        throw new SSLException("No X509TrustManager in TrustManagerFactory.");
    }
}
