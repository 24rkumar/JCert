package main;

import exceptions.InvalidFormatException;
import exceptions.InvalidHashException;
import exceptions.InvalidPublicKeyException;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;

public class CertFile extends File {
    private String formatVersion;
    public String keyHash;
    private String fileHash;

    public CertFile(String pathname) throws IOException, InvalidFormatException {
        super(pathname);

        if(this.isFile()) {
            BufferedReader br = new BufferedReader(new FileReader(this));
            formatVersion = br.readLine();

            switch (formatVersion) {
                case "JCERT 1" -> {
                    keyHash = br.readLine();
                    fileHash = br.readLine();
                }
                default -> throw new InvalidFormatException();
            }

            br.close();
        } else {
            this.createNewFile();
        }
    }

    private String getFileChecksum(MessageDigest digest, File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);

        byte[] byteArray = new byte[1024];
        int bytesCount;

        while ((bytesCount = fis.read(byteArray)) != -1) {
            digest.update(byteArray, 0, bytesCount);
        }

        fis.close();

        byte[] bytes = digest.digest();

        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

    public void createCertFile(KeyManager keyManager, File src) throws IOException, GeneralSecurityException {
        String publicKeyHash = Arrays.toString(
                MessageDigest.getInstance("SHA-256").digest(keyManager.getEncodedPublicKey())
        );
        String hash = Arrays.toString(
                keyManager.encrypt(
                        getFileChecksum(MessageDigest.getInstance("SHA-256"), src).getBytes(StandardCharsets.UTF_8)
                )
        );

        BufferedWriter bw = new BufferedWriter(new FileWriter(this));
        BufferedReader br = new BufferedReader(new FileReader(src));

        String LATEST_VERSION = "JCERT 1";
        bw.write(LATEST_VERSION + System.lineSeparator());
        bw.write(publicKeyHash + System.lineSeparator());
        bw.write(hash + System.lineSeparator());
        bw.write("==BEGIN FILE==" + System.lineSeparator());

        String line;
        while((line=br.readLine()) != null) {
            bw.write(line + System.lineSeparator());
        }

        bw.close();
        br.close();
    }

    public File openCertFile(PublicKey key) throws
            GeneralSecurityException,
            InvalidPublicKeyException,
            IOException,
            InvalidHashException
    {
        if(!Arrays.toString(
                MessageDigest.getInstance("SHA-256").digest(key.getEncoded())
        ).equals(keyHash)) {
            throw new InvalidPublicKeyException();
        }

        File destFile = new File("out", this.getName().substring(0, this.getName().lastIndexOf('.')));
        if(destFile.isFile()) {
            destFile.delete();
        }
        destFile.createNewFile();

        BufferedWriter bw = new BufferedWriter(new FileWriter(destFile));
        BufferedReader br = new BufferedReader(new FileReader(this));

        while(true) {
            if(br.readLine().equals("==BEGIN FILE==")) {
                break;
            }
        }

        String line;
        while((line=br.readLine()) != null) {
            bw.write(line + System.lineSeparator());
        }

        bw.close();
        br.close();

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, key);

        if(!Arrays.toString(decryptCipher.doFinal(fileHash.getBytes(StandardCharsets.UTF_8)))
                .equals(getFileChecksum(MessageDigest.getInstance("SHA-256"), destFile)))
        {
            destFile.delete();
            throw new InvalidHashException();
        }

        return destFile;
    }
}
