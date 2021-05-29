package main;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class PublicKeyManager {
    public boolean savedKeyExists(String keyHash) {
        return new File("keys" + File.separator + keyHash + ".key").isFile();
    }

    public void savePublicKey(PublicKey key, String name) throws NoSuchAlgorithmException, IOException {
        byte[] encodedKey = Base64.getEncoder().encode(key.getEncoded());
        byte[] keyHash = MessageDigest.getInstance("SHA-256").digest(encodedKey);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("name", name);
        jsonObject.put("key", Arrays.toString(encodedKey));

        FileWriter keyWriter = new FileWriter("keys" + File.separator + Arrays.toString(keyHash) + ".key");
        keyWriter.write(jsonObject.toString());
        keyWriter.close();
    }

    public PublicKey getSavedKey(String keyHash) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, ParseException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(
                Base64.getDecoder().decode(
                        ((JSONObject) new JSONParser().parse(
                                Arrays.toString(
                                        Files.readAllBytes(Path.of("keys" + File.separator + keyHash + ".key"))
                                )
                        )).get("key").toString()
                ))
        );
    }

    public String getSavedKeyName(String keyHash) throws IOException, ParseException {
        return ((JSONObject) new JSONParser().parse(
                Arrays.toString(Files.readAllBytes(Path.of("keys" + File.separator + keyHash + ".key")))
        )).get("name").toString();
    }

    public void deleteSavedKey(String keyHash) {
        new File("keys" + File.separator + keyHash + ".key").delete();
    }
}
