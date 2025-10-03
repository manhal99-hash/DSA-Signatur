package Krypto2;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

public class DSA_Schluessel {
    public static void main(String[]args) throws Exception {

        //Teil1 der Aufgabe : generieren ein DSA schlüssel und der private, öffentlicher Schlüssel

        //DSA schlüsselgenerator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        /*
        Merke : bei schlüssellänge von 3000bit wird ein Fehler rauskommen, da in java nur bis zu 1024 bits
        verfügbar ist
         */

        //generieen das schlüsselpaar
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        //private und öffentlicher schlüssel
        DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();
        DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();

        //hier kommt die DSA Schlüsselparametern
        BigInteger p = privateKey.getParams().getP(); //eine große primzahl
        BigInteger q = privateKey.getParams().getQ(); // ein primzahl q die als Teil von p-1 (Gruppenelement)
        BigInteger g = privateKey.getParams().getG(); //der generator g
        BigInteger x = privateKey.getX(); //der private schlüssel x
        BigInteger y = publicKey.getY(); // öffentlicher schlüssel y (g^x mod p)

        //ausgeben alle Parametern auf dem Bildschirm
        System.out.println("\nDas sind die DSA Schlüsselparametern: ");
        System.out.println("p: " + p);
        System.out.println("q: " + q);
        System.out.println("g: "+ g);
        System.out.println("x: "+ x);
        System.out.println("y: "+ y+"\n");

        //Teil2 der Aufgabe

        //Hashing einer Nachricht mit SHA-256
        String nachricht = "123456789";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] gehashteNachricht = digest.digest(nachricht.getBytes(StandardCharsets.UTF_8));

        //Signieren der gehashte Nachricht mit DSA-Signatur also privater Schlüssel
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initSign(privateKey); //privater schlüssel für DSA
        dsa.update(gehashteNachricht);
        byte[] signature = dsa.sign();//signieren der Nachricht

        //Verifizieren der Nachricht mit dem öffentlicher Schlüssel
        Signature dsaVerfizierer = Signature.getInstance("SHA256withDSA");
        dsaVerfizierer.initVerify(publicKey);
        dsaVerfizierer.update(gehashteNachricht);
        boolean istVerifiziert = dsaVerfizierer.verify(signature);//verifizieren der signerte Nachrict

        System.out.println("Gehashte Nachricht: "+bytesToHex(gehashteNachricht));
        System.out.println("Signatur: "+bytesToHex(signature));
        System.out.println("Signatur verifiziert: "+(istVerifiziert ? "Ja" : "Nein"));

    }

    //private methode um um ein byte in einen hex-string umzuwandeln
    private static String bytesToHex(byte[] bytes){
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes){
            sb.append(String.format("%02x",b));
        }
        return sb.toString();
    }
}
