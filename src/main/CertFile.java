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
import java.util.Base64;

public class CertFile extends File {
    private String formatVersion;
    public String keyHash;
    private String fileHash;
    private String newline;

    public CertFile(String pathname, boolean openingFile) throws IOException, InvalidFormatException {
        super(pathname);

        if(openingFile) {
            if (this.isFile()) {
                BufferedReader br = new BufferedReader(new FileReader(this));
                formatVersion = br.readLine();

                switch (formatVersion) {
                    case "JCERT 1" -> {
                        keyHash = br.readLine();
                        fileHash = br.readLine();
                        newline = switch (br.readLine()) {
                            case "CR" -> "\r";
                            case "CRLF" -> "\r\n";
                            case "LF" -> "\n";

                            default -> throw new InvalidFormatException();
                        };
                    }
                    default -> {
                        br.close();
                        throw new InvalidFormatException();
                    }
                }

                br.close();
            } else {
                throw new FileNotFoundException();
            }
        } else {
            if(this.isFile()) {
                this.delete();
            }
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

        return toHex(bytes);
    }

    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }

        return sb.toString();
    }

    private String detectEOL(File file) throws IOException {
        Reader r = new FileReader(file);

        int i;
        while((i = r.read()) != -1) {
            if(i == '\r') {
                i = r.read();
                return (i == '\n')
                        ?"\r\n"
                        :"\r";
            } else if(i == '\n'){
                return "\n";
            }
        }

        return System.lineSeparator();
    }

    public void createCertFile(KeyManager keyManager, File src) throws IOException, GeneralSecurityException {
        String publicKeyHash = toHex(
                MessageDigest.getInstance("SHA-256").digest(keyManager.getEncodedPublicKey())
        );
        String hash = Base64.getEncoder().encodeToString(
                keyManager.encrypt(
                        getFileChecksum(MessageDigest.getInstance("SHA-256"), src).getBytes(StandardCharsets.UTF_8)
                )
        );
        String eol = switch(detectEOL(src)) {
            case "\r" -> "CR";
            case "\r\n" -> "CRLF";
            case "\n" -> "LF";

            default -> throw new IllegalStateException("Unexpected value: " + detectEOL(src));
        };

        BufferedWriter bw = new BufferedWriter(new FileWriter(this));
        BufferedReader br = new BufferedReader(new FileReader(src));

        String LATEST_VERSION = "JCERT 1";
        bw.write(LATEST_VERSION + System.lineSeparator());
        bw.write(publicKeyHash + System.lineSeparator());
        bw.write(hash + System.lineSeparator());
        bw.write(eol + System.lineSeparator());
        bw.write("==BEGIN FILE==" + System.lineSeparator());

        String line = br.readLine();

        if (line != null) {
            bw.write(line);
        }

        while((line=br.readLine()) != null) {
            bw.write(System.lineSeparator() + line);
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
        if(!toHex(
                MessageDigest.getInstance("SHA-256").digest(Base64.getEncoder().encode(key.getEncoded()))
        ).equals(keyHash)) {
            throw new InvalidPublicKeyException();
        }

        File destFile = new File("output", this.getName().substring(0, this.getName().lastIndexOf('.')));
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

        String line = br.readLine();

        if (line != null) {
            bw.write(line);
        }

        while((line=br.readLine()) != null) {
            bw.write(newline + line);
        }

        bw.close();
        br.close();

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, key);

        if(!new String(decryptCipher.doFinal(Base64.getDecoder().decode(fileHash)))
                .equals(getFileChecksum(MessageDigest.getInstance("SHA-256"), destFile)))
        {
            //destFile.delete();
            throw new InvalidHashException();
        }

        return destFile;
    }
}
