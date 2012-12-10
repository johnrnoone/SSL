package sslexample;

// This program creates a digital signature of the data in textfile.txt using
// either of the key files in /User/John (keystore2048.jks and keystore2048.truststore).
// The trust file mybroker.ts didn't work.

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

public class DigitalSig {

	public static void main(String[] arstring) {

		System.out.println ("This is DigitalSig.main()");
		List<String> text = new ArrayList<String>();

		String keyStore = "keystore2048.jks";
		String trustStore = "keystore2048.truststore";
		String sslAlias = "selfsigned";
		boolean requestPrivate = true;

		PrivateKey privateKey;

		try {
			String alias = sslAlias;
			String storeName = keyStore;

			privateKey = (PrivateKey) getKey (storeName, alias, requestPrivate);
			System.out.println ("DigitalSig.getKey() returns a key " + privateKey.toString());

			
			File f = new File ("textfile.txt");
			text = readFile (f);

			byte[] signature = computeSignature (privateKey, text);
			System.out.println ("computeSignature() returns a signature " + signature.toString());

			// To verify signature, set keystore to the consumer
			alias = sslAlias; storeName = trustStore;
			PublicKey publicKey = (PublicKey) getKey (storeName, alias, !requestPrivate);
			System.out.println ("DigitalSig.getKey() returns a public key " + publicKey.toString());

			boolean verify = verifySignature (publicKey, signature, text);
			if (verify) System.out.println ("The signature is verified");
			else System.out.println ("The signature is not verified");


		} catch (Exception exception) {
			System.out.println ("DigitalSig detects exception");
			exception.printStackTrace();
		}

	}

	public static byte[] computeSignature (PrivateKey key, List<String>data) {
		byte[] signature = null;
		String cypher = getCypher();

		try {

			Signature s = Signature.getInstance(cypher);
			s.initSign(key);
			for (String line : data) {
				byte[] byteBuff = line.getBytes();
				s.update(byteBuff);
			}
			signature = s.sign();

		} catch (NoSuchAlgorithmException nsa) {
			System.out.println ("computeSignature detects NoSuchAlgorithmException");
			nsa.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println ("computeSignature detects InvalidKeyException");
			e.printStackTrace();
		} catch (SignatureException e) {
			System.out.println ("computeSignature detects SignatureException");
			e.printStackTrace();
		}

		return signature;
	}

	public static List<String> readFile (File fileObj) {
		List<String> text = new ArrayList<String>();
		try {
			FileInputStream fis = new FileInputStream (fileObj);
			InputStreamReader isr = new InputStreamReader(fis);
			BufferedReader br = new BufferedReader(isr);
			for (String line; (line = br.readLine()) != null; text.add(line)) ;
			br.close();
		} catch (Exception exception) {
			exception.printStackTrace();
		}
		return text;
	}

	public static Key getKey (String store, String alias, boolean requestPrivateKey) {
		Key key = null;
		String storePass = "password";
		String filePass = "password";
		String home = System.getProperty("user.home");
		System.out.println ("getKey() for alias, " + alias + " using store = " + store);
		File homeDir = new File (home);

		try {
			File keyFile = new File (homeDir, store);
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			BufferedInputStream bis = new BufferedInputStream (new FileInputStream (keyFile));
			keyStore.load(bis, filePass.toCharArray());
			System.out.println ("keyStore loads " + keyStore.size() + " entries");
			if (requestPrivateKey) {
				System.out.println ("getKey calls ks.getKey for alias = " + alias);
				key = keyStore.getKey(alias, storePass.toCharArray());
			} else {
				System.out.println ("getKey gets public cert for alias = " + alias);
				java.security.cert.Certificate cert = keyStore.getCertificate(alias);
				System.out.println ("getKey got a, now get a public key");
				key = (Key)cert.getPublicKey();
			}
		} catch (NoSuchAlgorithmException nsa) {
			System.out.println ("getKey detects NoSuchAlgorithmException");
			nsa.printStackTrace();
		} catch (KeyStoreException e) {
			System.out.println ("getKey detects KeyStoreException");
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			System.out.println ("getKey detects FileNotFoundException");
			e.printStackTrace();
		} catch (CertificateException e) {
			System.out.println ("getKey detects CertificateException");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println ("getKey detects IOException");
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			System.out.println ("getKey detects UnrecoverableKeyException");
			e.printStackTrace();
		}
		return key;
	}

	public static boolean verifySignature (PublicKey key, byte[] signature, List<String> data) {
		boolean verified = false;
		String cypher = getCypher();

		try {
			Signature s = Signature.getInstance(cypher);
			s.initVerify(key);
			for (String line : data) {
				byte[] byteBuff = line.getBytes();
				s.update(byteBuff);
			}
			verified = s.verify(signature);

		} catch (NoSuchAlgorithmException nsa) {
			System.out.println ("verifySignature detects NoSuchAlgorithmException");
			nsa.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println ("verifySignature detects InvalidKeyException");
			e.printStackTrace();
		} catch (SignatureException e) {
			System.out.println ("verifySignature detects SignatureException");
			e.printStackTrace();
		}
		return verified;
	}

	public static String getCypher() {
		//  	String cypher = "SHA1withDSA";  // No installed provider supports this key: 
		// sun.security.rsa.RSAPrivateCrtKeyImpl
		//      String cypher = "SSL_RSA_WITH_RC4_128_MD5";   // NoSuchAlgorithmException
		//      String cypher = "MD2withRSA";     // works
		String cypher = "MD5withRSA";     // works
		//      String cypher = "SHA1withRSA";    // works
		return cypher;
	}

}
