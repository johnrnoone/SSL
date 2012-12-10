package sslexample;

	// This program creates a signed object containing the data in textfile.txt, the
	// signature of an installed cypher, and the private key in the keystore2048 keystore.
	// The program then verifies the object using the public key for the alias 'selfsigned'
	// from the keystore2048.truststore file.

// Note all key files are saved in /Users/John


	import java.io.BufferedInputStream;
	import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
	import java.io.File;
	import java.io.FileInputStream;
	import java.io.FileNotFoundException;
import java.io.FileOutputStream;
	import java.io.IOException;
	import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;

	import java.security.InvalidKeyException;
	import java.security.Key;
	import java.security.KeyStore;
	import java.security.KeyStoreException;
	import java.security.NoSuchAlgorithmException;
	import java.security.PrivateKey;
	import java.security.PublicKey;
	import java.security.Signature;
	import java.security.SignatureException;
import java.security.SignedObject;
	import java.security.UnrecoverableKeyException;
	import java.security.cert.CertificateException;
	import java.util.ArrayList;
import java.util.List;

	public class SignedObj {

		public static void main(String[] arstring) {

			System.out.println ("This is SignedObj.main()");
			List<String> text = new ArrayList<String>();

			String keyStore = "keystore2048.jks";
			String trustStore = "keystore2048.truststore";
			String sslAlias = "selfsigned";
			boolean requestPrivate = true;

			Serializable o;
			PrivateKey privateKey;

			try {
				String alias = sslAlias;
				String storeName = keyStore;

				privateKey = (PrivateKey) getKey (storeName, alias, requestPrivate);
				
				File f = new File ("textfile.txt");
				text = readFile (f);

				Signature  s = getSignature ();

				SignedObject so = new SignedObject ((Serializable) text, privateKey, s);
				System.out.println ("SignedObj.main() computes signed object so");
				
				byte[] payload   = serializeObject (so);
				SignedObject dso = deserializeObject (payload);

				System.out.println(dso);

				// To verify signature, set keystore to the consumer
				alias = sslAlias; storeName = trustStore;
				PublicKey publicKey = (PublicKey) getKey (storeName, alias, !requestPrivate);
//				System.out.println ("SignedObj.getKey() returns a public key " + publicKey.toString());

				boolean verify = verifySignedObject (publicKey, so);
				if (verify) System.out.println ("The object is verified");
				else System.out.println ("The object is not verified");


			} catch (Exception exception) {
				System.out.println ("SignedObj detects exception");
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
			BufferedReader br = null;
			try {
	/*			FileInputStream fis = new FileInputStream (fileObj);
				InputStreamReader isr = new InputStreamReader(fis);
				BufferedReader br = new BufferedReader(isr); */
				br =
					new BufferedReader(new InputStreamReader(new FileInputStream (fileObj)));
				for (String line; (line = br.readLine()) != null; text.add(line)) ;
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
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

		public static boolean verifySignedObject (PublicKey key, SignedObject so) {
			boolean verified = false;
			String cypher = getCypher();
			try {
				Signature s = Signature.getInstance(cypher);
				verified = so.verify(key, s);
				Object o = so.getObject();
			} catch (NoSuchAlgorithmException nsa) {
				System.out.println ("verifySignature detects NoSuchAlgorithmException");
				nsa.printStackTrace();
			} catch (InvalidKeyException e) {
				System.out.println ("verifySignature detects InvalidKeyException");
				e.printStackTrace();
			} catch (SignatureException e) {
				System.out.println ("verifySignature detects SignatureException");
				e.printStackTrace();
			} catch (IOException e) {
				System.out.println ("verifySignature detects IOException");
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
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
		
		public static Signature getSignature() {
				//  	String cypher = "SHA1withDSA";  // No installed provider supports this key: 
				// sun.security.rsa.RSAPrivateCrtKeyImpl
				//      String cypher = "SSL_RSA_WITH_RC4_128_MD5";   // NoSuchAlgorithmException
				//      String cypher = "MD2withRSA";     // works
				String cypher = "MD5withRSA";     // works
				//      String cypher = "SHA1withRSA";    // works
				Signature s = null;
				try {
					s = Signature.getInstance(cypher);
				} catch (NoSuchAlgorithmException e) {
					System.out.println ("verifySignature detects NoSuchAlgorithmException");
					e.printStackTrace();
				}
				return s;			
		}
		
		public static byte[] serializeObject (Serializable so) {
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ObjectOutputStream out;
			try {
				out = new ObjectOutputStream(bOut);
				out.writeObject(so);
				out.close();
			} catch (IOException e) {
				System.out.println ("IOException in serializeObject");
				e.printStackTrace();
			}
			return bOut.toByteArray();		
		}
		
		public static SignedObject deserializeObject (byte[] dso) {
			ObjectInputStream in;
			SignedObject so = null;
			try {
				ByteArrayInputStream bIn = new ByteArrayInputStream(dso);
				in = new ObjectInputStream(bIn);
				so = (SignedObject) in.readObject();
				in.close();		
			} catch (IOException e) {
				System.out.println ("IOException in deserializeObject");
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				System.out.println ("ClassNotFoundException in deserializeObject");
				e.printStackTrace();
			}
			return so;
		}

	}

