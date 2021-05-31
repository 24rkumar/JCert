package main;

import exceptions.InvalidFormatException;
import exceptions.InvalidHashException;
import exceptions.InvalidPublicKeyException;
import org.json.simple.parser.ParseException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws IOException, ParseException, GeneralSecurityException, InvalidFormatException {
        final double VERSION = 1.0;

        System.out.println("JCERT v" + VERSION);

        Scanner scanner = new Scanner(System.in);

        KeyManager keyManager = new KeyManager();

        while(true) {
            System.out.println("""
                    Please select a choice:
                                    
                    0. Exit
                    1. Open JCERT file
                    2. Create a new JCERT file
                    3. Generate new keys
                    """);

            System.out.print("Choice: ");
            String choice = scanner.nextLine();

            switch (choice) {
                case "0" -> System.exit(0);
                case "1" -> openCert(scanner);
                case "2" -> createCert(scanner, keyManager);
                case "3" -> generateKeys(scanner, keyManager);
                default -> System.out.println("Invalid choice\n");
            }
        }
    }

    public static void openCert(Scanner scanner) throws IOException, ParseException, GeneralSecurityException {
        System.out.print("Enter path to JCert file: ");
        String path = scanner.nextLine();

        CertFile certFile;

        try {
            certFile = new CertFile(path, true);
        } catch (FileNotFoundException e) {
            System.out.println("Error: File not found");
            return;
        } catch (IOException e) {
            System.out.println("Error: Path specified is either invalid or there was an error reading from the file");
            return;
        } catch (InvalidFormatException e) {
            System.out.println("Error: File specified is in an invalid or unsupported format");
            return;
        }

        PublicKey key;

        if(PublicKeyManager.savedKeyExists(certFile.keyHash)) {
            System.out.printf("""
                    Associated key for file is saved under name:
                    
                    %s
                    
                    """, PublicKeyManager.getSavedKeyName(certFile.keyHash));
            while(true) {
                System.out.print("Would you like to continue opening this file? (Y/N): ");
                String choice = scanner.nextLine();

                if(choice.equalsIgnoreCase("N")) {
                    return;
                } else if (choice.equalsIgnoreCase("Y")) {
                    break;
                } else {
                    System.out.println("Invalid choice");
                }
            }

            key = PublicKeyManager.getSavedKey(certFile.keyHash);
        } else {
            while(true) {
                System.out.print("Enter path to public key file associated with JCert file: ");
                path = scanner.nextLine();

                try {
                    key = PublicKeyManager.getKeyFromFile(new File(path));
                    break;
                } catch (IOException e) {
                    System.out.println("Error: Path specified is either invalid or there was an error reading from the file");
                } catch (IllegalArgumentException e) {
                    System.out.println("Error: Public key file is invalid");
                }
            }
        }

        try {
            System.out.printf("JCert file verification successful. The opened file can be found at %s%n", certFile.openCertFile(key).getCanonicalPath());

            if(!PublicKeyManager.savedKeyExists(certFile.keyHash)) {
                while (true) {
                    System.out.print("Would you like to save this key? (Y/N): ");
                    String choice = scanner.nextLine();

                    if (choice.equalsIgnoreCase("Y")) {
                        System.out.print("Enter name of key issuer: ");
                        choice = scanner.nextLine();
                        PublicKeyManager.savePublicKey(key, choice);
                        System.out.println("Public key has been saved.");
                        break;
                    } else if (choice.equalsIgnoreCase("N")) {
                        break;
                    } else {
                        System.out.println("Invalid choice");
                    }
                }
            }

        } catch (InvalidPublicKeyException e) {
            System.out.println("The public key that was specified does not correspond to the certificate file");
        } catch (InvalidHashException e) {
            System.out.println("Verification failed - file tampering detected.");
        }
    }

    public static void createCert(Scanner scanner, KeyManager keyManager) throws IOException, InvalidFormatException, GeneralSecurityException {
        if(!keyManager.keyExists()) {
            System.out.println("Error: public/private keys not found. Please generate them before creating jcert files.");
            return;
        }

        keyManager.refreshKeys();

        System.out.println("Please note that only plaintext and UTF-8 encoded files are supported in this version.");
        System.out.print("Enter path to file: ");
        File file = new File(scanner.nextLine());

       if(!file.isFile()) {
           System.out.println("Error: Specified path is invalid or file not found.");
           return;
       }

       CertFile certFile = new CertFile("output" + File.separator + file.getName() + ".jcert", false);

       certFile.createCertFile(keyManager, file);

       System.out.printf("""
               .jcert file has been successfully created at %s
               Be sure to include your public key also, which is found at %s
               """, certFile.getCanonicalPath(), new File(".").getCanonicalPath() + File.separator + "public.key");
    }

    public static void generateKeys(Scanner scanner, KeyManager keyManager) throws GeneralSecurityException, IOException {
        if(keyManager.keyExists()) {
            while (true) {
                System.out.println("""
                        Warning: Continuing will overwrite existing keys.
                        Certificates generated in the past will no longer be verifiable without the old public key.
                        """);
                System.out.print("Are you sure you want to continue? (Y/N): ");
                String choice = scanner.nextLine();

                if(choice.equalsIgnoreCase("Y")) {
                    break;
                } else if(choice.equalsIgnoreCase("N")) {
                    return;
                } else {
                    System.out.println("Invalid choice");
                }

            }
        }

        keyManager.generateKeys();
        System.out.println("New key generation successful");
        System.out.println("Never share your private key. Doing so poses the risk of others being able to send files as you.");
        System.out.printf("Your public key can be found at %s%n", new File(".").getCanonicalPath() + File.separator + "public.key");
    }
}
