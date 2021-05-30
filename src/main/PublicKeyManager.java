package main;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class PublicKeyManager {
    public boolean savedKeyExists(String keyHash) {
        return new File("keys", keyHash + ".key").isFile();
    }

    public void savePublicKey(PublicKey key, String name) throws GeneralSecurityException, IOException {
        byte[] encodedKey = Base64.getEncoder().encode(key.getEncoded());
        byte[] keyHash = MessageDigest.getInstance("SHA-256").digest(encodedKey);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("name", name);
        jsonObject.put("key", Arrays.toString(encodedKey));

        File keyFile = new File("keys", Arrays.toString(keyHash) + ".key");
        keyFile.createNewFile();
        FileWriter keyWriter = new FileWriter(keyFile);
        keyWriter.write(jsonObject.toString());
        keyWriter.close();
    }

    public PublicKey getSavedKey(String keyHash) throws IOException, GeneralSecurityException, ParseException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(
                Base64.getDecoder().decode(
                        ((JSONObject) new JSONParser().parse(
                                Arrays.toString(
                                        Files.readAllBytes(Path.of("keys", keyHash + ".key"))
                                )
                        )).get("key").toString()
                ))
        );
    }

    public String getSavedKeyName(String keyHash) throws IOException, ParseException {
        return ((JSONObject) new JSONParser().parse(
                Arrays.toString(Files.readAllBytes(Path.of("keys", keyHash + ".key")))
        )).get("name").toString();
    }

    public void deleteSavedKey(String keyHash) {
        new File("keys", keyHash + ".key").delete();
    }
}
