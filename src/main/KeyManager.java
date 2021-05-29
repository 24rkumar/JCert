package main;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class KeyManager {
    final File publicKeyFile = new File("public.key");
    final File privateKeyFile = new File("keys" + File.separator + "private.key");

    PublicKey publicKey;
    PrivateKey privateKey;

    public void generateKeys() throws NoSuchAlgorithmException, IOException {
        if(publicKeyFile.isFile()) {
            publicKeyFile.delete();
        }
        if(privateKeyFile.isFile()) {
            privateKeyFile.delete();
        }

        FileWriter publicKeyWriter = new FileWriter(publicKeyFile);
        FileWriter privateKeyWriter = new FileWriter(publicKeyFile);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();

        publicKeyWriter.write(Arrays.toString(Base64.getEncoder().encode(publicKey.getEncoded())));
        privateKeyWriter.write(Arrays.toString(Base64.getEncoder().encode(privateKey.getEncoded())));

        publicKeyWriter.close();
        privateKeyWriter.close();
    }

    public void refreshKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(Files.readAllBytes(publicKeyFile.toPath()));
        byte[] privateKeyBytes = Base64.getDecoder().decode(Files.readAllBytes(privateKeyFile.toPath()));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        privateKey = keyFactory.generatePrivate(new X509EncodedKeySpec(privateKeyBytes));
    }

    public boolean keyExists() {
        return publicKeyFile.isFile() && privateKeyFile.isFile();
    }

    public byte[] encrypt(byte[] message) throws
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException
    {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return encryptCipher.doFinal(message);
    }
}
