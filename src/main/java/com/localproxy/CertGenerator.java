package com.localproxy;

import java.io.*;
import java.nio.file.*;
import java.security.*;

/**
 * Generates a self-signed PKCS12 keystore using the JDK keytool command.
 * Works with any JDK 11+ without Bouncy Castle or sun.security internals.
 */
public class CertGenerator {

    public static KeyStore generateKeyStore(String ipAddress) throws Exception {
        // Temp file for the keystore
        Path ksPath = Files.createTempFile("local-https-proxy-", ".p12");
        Files.delete(ksPath); // keytool needs file to NOT exist
        ksPath.toFile().deleteOnExit();

        String ksFile = ksPath.toAbsolutePath().toString();
        String password = "password";

        // SAN includes both IP and DNS entries
        String san = "ip:" + ipAddress + ",ip:127.0.0.1,dns:localhost";

        // Find keytool next to the running JVM
        String javaHome = System.getProperty("java.home");
        String keytool = javaHome + File.separator + "bin" + File.separator + "keytool";
        if (!new File(keytool).exists()) {
            keytool = "keytool"; // fall back to PATH
        }

        String[] cmd = {
            keytool,
            "-genkeypair",
            "-alias",    "proxy",
            "-keyalg",   "RSA",
            "-keysize",  "2048",
            "-validity", "3650",
            "-dname",    "CN=LocalHTTPSProxy, O=LocalDev, C=TR",
            "-ext",      "SAN=" + san,
            "-ext",      "BasicConstraints=ca:true",
            "-keystore", ksFile,
            "-storetype","PKCS12",
            "-storepass", password,
            "-keypass",   password,
            "-noprompt"
        };

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String output = new String(p.getInputStream().readAllBytes());
        int exit = p.waitFor();

        if (exit != 0) {
            throw new RuntimeException("keytool failed (exit " + exit + "):\n" + output);
        }

        // Load and return the keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = Files.newInputStream(ksPath)) {
            ks.load(is, password.toCharArray());
        }
        return ks;
    }
}
