import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ichecker {

	private static String privateKeyFilePath;
	private static String certificateFile;
	private static String regFile;
	private static String path;
	private static String logFile;
	private static String hash;
	private static final String meaningfulText = "This is a private key and we encrypted with your password";

	public static void main(String[] args) throws Exception {

		readCommandsLine(args);

		if (args[0].equals("createCert")) {
			createCert();
		} else if (args[0].equals("createReg")) {
			createReg();
		} else if (args[0].equals("check")) {
			check();
		} else {
			System.out.println("Undefined Function");
			System.exit(0);
		}

	}

	private static void check() throws Exception {

		String publicKey = getPublicKey();
		File reg = new File(regFile);
		File log = new File(logFile);
		String regFileContent = readFile(reg);
		String[] parts = regFileContent.split("\\n");
		String allmessages = "";
		String sign = "";
		for (int i = 0; i < parts.length; i++) {
			if (i == parts.length - 1) {
				sign = parts[i];
			} else {
				allmessages = allmessages + parts[i];
			}
		}
		boolean verify = verifySignature(allmessages, sign, publicKey);
		if (!verify) {
			String message = currentTime() + "Registry file verification failed!";
			writeFile(log, message);
			System.exit(0);
		}
		checkFiles(regFileContent);

	}

	public static boolean verifySignature(String plainText, String signature, String publicKey) throws Exception {

		String firstMessage = "-----BEGIN PUBLIC KEY-----";
		String lastMessage = "-----END PUBLIC KEY-----";

		int firstIndex = publicKey.indexOf(firstMessage);
		int lastIndex = publicKey.indexOf(lastMessage);
		String originalKey = publicKey.substring(firstIndex + (firstMessage.length()), lastIndex).replaceAll("\\r|\\n",
				"");

		KeyFactory kf = KeyFactory.getInstance("RSA");

		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(originalKey));
		RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

		if (hash.equals("SHA-256")) {
			Signature publicSignature = Signature.getInstance("SHA256withRSA");
			publicSignature.initVerify(pubKey);
			publicSignature.update(plainText.getBytes());

			byte[] signatureBytes = Base64.getDecoder().decode(signature);

			return publicSignature.verify(signatureBytes);
		} else {
			Signature publicSignature = Signature.getInstance("MD5withRSA");
			publicSignature.initVerify(pubKey);
			publicSignature.update(plainText.getBytes());
			byte[] signatureBytes = Base64.getDecoder().decode(signature);
			return publicSignature.verify(signatureBytes);
		}

	}

	public static String getPublicKey() throws IOException {
		String command = "openssl x509 -inform pem -in " + certificateFile
				+ ".cer -pubkey -noout > certificate_publickey.pem";
		commandExecute(command);
		File publicFile = new File("certificate_publickey.pem");
		String publicKey = readFile(publicFile);
		return publicKey;

	}

	public static void createReg() throws Exception {
		Scanner sc = new Scanner(System.in);
		System.out.print("Enter a password for decrypt: ");
		String password = sc.nextLine();
		System.out.println("You have entered: " + password);

		File log = new File(logFile);

		SecretKey secretKey = stringToKey(getMd5(password));
		File privateKeyFile = new File(privateKeyFilePath);

		try {
			String decryptText = decryptFile(privateKeyFile, secretKey);

			if (findText(meaningfulText, decryptText)) {

				File directory = new File(path);
				File register = new File(regFile);
				deleteFile(register);
				String[] subfiles = directory.list();

				String message = currentTime() + "Registry file is created at [" + regFile + "]!";
				writeFile(log, message);
				String allmessage = "";

				if (hash.equals("MD5")) {

					for (String subfile : subfiles) {

						String subpath = path + "/" + subfile;

						File sub_file = new File(subpath);
						String subFileHash = getMd5(readFile(sub_file));

						String registerText = subpath + " " + subFileHash;
						allmessage = allmessage + registerText;
						writeFile(register, registerText);
						String submessage = currentTime() + " " + subpath + " is added to registry.";
						writeFile(log, submessage);
					}

					writeFile(register, generateSign("MD5", decryptText, allmessage));

				} else if (hash.equals("SHA-256")) {

					for (String subfile : subfiles) {
						String subpath = path + "/" + subfile;

						File sub_file = new File(subpath);
						String subFileHash = getSHA(readFile(sub_file));
						String registerText = subpath + " " + subFileHash;
						allmessage = allmessage + registerText;

						writeFile(register, registerText);
						String submessage = currentTime() + " " + subpath + " is added to registry.";
						writeFile(log, submessage);
					}
					writeFile(register, generateSign("SHA-256", decryptText, allmessage));
				}

				String lastMessage = currentTime() + subfiles.length + " files are added to the registry and registry"
						+ "creation is finished!";
				writeFile(log, lastMessage);

			} else {
				String message = currentTime() + "Wrong password attempt!";
				writeFile(log, message);
				System.exit(0);
			}
		} catch (Exception e) {

			String message = currentTime() + "Wrong password attempt!";
			writeFile(log, message);
			System.exit(0);
		}

	}

	public static void checkFiles(String regFileContent) throws IOException {

		File log = new File(logFile);
		String[] fileContent = regFileContent.split("\\s+");

		File directory = new File(path);
		String[] subfiles = directory.list();
		String allSubPath = "";
		boolean directoryModify = false;
		if (hash.equals("MD5")) {

			for (String subfile : subfiles) {

				String subpath = path + "/" + subfile;
				allSubPath += subpath;
				String oldHash = "";

				File sub_file = new File(subpath);
				String subFileHash = getMd5(readFile(sub_file));

				if (findText(subpath, regFileContent)) {
					for (int i = 0; i < fileContent.length; i++) {
						if (fileContent[i].equals(subpath)) {
							oldHash = fileContent[i + 1];
						}
					}
					if (oldHash.equals(subFileHash)) {
						;
					} else {
						directoryModify = true;
						writeFile(log, currentTime() + " " + subpath + " is altered");
					}
				} else {
					directoryModify = true;
					writeFile(log, currentTime() + " " + subpath + " is created");
				}
			}
			for (int i = 0; i < fileContent.length / 2; i++) {
				if (!findText(fileContent[2 * i], allSubPath)) {
					directoryModify = true;
					writeFile(log, currentTime() + " " + fileContent[2 * i] + " is deleted");
				}
			}
			if (!directoryModify) {
				writeFile(log, currentTime() + "  The directory is checked and no change is detected!");
			}

		} else if (hash.equals("SHA-256")) {
			for (String subfile : subfiles) {

				String subpath = path + "/" + subfile;
				String oldHash = "";

				File sub_file = new File(subpath);
				String subFileHash = getSHA(readFile(sub_file));

				if (findText(subpath, regFileContent)) {
					for (int i = 0; i < fileContent.length; i++) {
						if (fileContent[i].equals(subpath)) {
							oldHash = fileContent[i + 1];
						}
					}
					if (oldHash.equals(subFileHash)) {
						;
					} else {
						directoryModify = true;
						writeFile(log, currentTime() + " " + subpath + " is altered");
					}
				} else {
					directoryModify = true;
					writeFile(log, currentTime() + " " + subpath + " is created");
				}
			}
			for (int i = 0; i < fileContent.length / 2; i++) {
				if (!findText(fileContent[2 * i], allSubPath)) {
					directoryModify = true;
					writeFile(log, currentTime() + " " + fileContent[2 * i] + " is deleted");
				}
			}
			if (!directoryModify) {
				writeFile(log, currentTime() + "  The directory is checked and no change is detected!");
			}

		}

	}

	public static String generateSign(String mode, String keyContext, String messages) throws Exception {

		String firstMessage = "-----BEGIN PRIVATE KEY-----";
		String lastMessage = "-----END PRIVATE KEY-----";
		int firstIndex = keyContext.indexOf(firstMessage);
		int lastIndex = keyContext.indexOf(lastMessage);
		String originalKey = keyContext.substring(firstIndex + (firstMessage.length()), lastIndex).replaceAll("\\r|\\n",
				"");
		KeyFactory kf = KeyFactory.getInstance("RSA");

		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(originalKey));
		PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

		if (mode.equals("MD5")) {

			Signature privateSignature = Signature.getInstance("MD5withRSA");
			privateSignature.initSign(privKey);
			privateSignature.update(messages.getBytes());
			byte[] signature = privateSignature.sign();
			return Base64.getEncoder().encodeToString(signature);
		} else {
			Signature privateSignature = Signature.getInstance("SHA256withRSA");
			privateSignature.initSign(privKey);
			privateSignature.update(messages.getBytes());
			byte[] signature = privateSignature.sign();
			return Base64.getEncoder().encodeToString(signature);
		}
	}

	public static String currentTime() {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		return "[" + dtf.format(now) + "] : ";
	}

	public static void createCert() throws Exception {

		Scanner sc = new Scanner(System.in);
		System.out.print("Enter a password for encrypt: ");
		String password = sc.nextLine();
		System.out.print("You have entered: " + password);

		SecretKey secretKey = stringToKey(getMd5(password));

		

		String genKeyPair = "keytool -genkeypair -dname \"cn=furkan, ou=Java, o=Oracle, c=US\""
				+ " -alias homework -keystore keystore.jks -storepass  123456"
				+ " -validity 180 -keyalg RSA -keysize 2048 -keypass 123456";
		commandExecute(genKeyPair);

		String jksToPk12 = "keytool -importkeystore -dname \"cn=furkan, ou=Java, o=Hacettepe, c=TR\""
				+ " -srckeystore keystore.jks -srcstoretype JKS" + " -srcalias homework"
				+ " -destkeystore keystore.p12 -deststoretype PKCS12"
				+ " -deststorepass 123456 -destkeypass 123456 -srcstorepass 123456";
		commandExecute(jksToPk12);
		String getPrivateKey = "openssl pkcs12 -in keystore.p12  -nodes -nocerts -password pass:123456 -out "
				+ privateKeyFilePath;
		commandExecute(getPrivateKey);
		String createCSR = "keytool -certreq -keystore keystore.jks  -alias homework -keyalg rsa -file CSR.csr -storepass 123456";
		commandExecute(createCSR);
		String createCa = "keytool -gencert -rfc -alias homework -keystore keystore.jks -keypass 123456 -outfile "
				+ certificateFile + ".cer -infile CSR.csr -storepass 123456";
		commandExecute(createCa);

		String deleteJks = "rm keystore.jks";
		String deletep12 = "rm keystore.p12";
		String deleteCsr = "rm CSR.csr";



		commandExecute(deleteJks);
		commandExecute(deletep12);
		commandExecute(deleteCsr);

		File privateKeyFile = new File(privateKeyFilePath);
		writeFile(privateKeyFile, meaningfulText);
		encryptFile(privateKeyFile, secretKey);

	}

	public static void commandExecute(String command) throws IOException {

		ProcessBuilder processBuilder = new ProcessBuilder();

		processBuilder.command("/bin/bash", "-c", "" + command);

		try {

			Process process = processBuilder.start();

			int exitCode = process.waitFor();

		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public static void readCommandsLine(String args[]) {
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-k")) {
				privateKeyFilePath = args[i + 1];
			} else if (args[i].equals("-c")) {
				certificateFile = args[i + 1];
			} else if (args[i].equals("-r")) {
				regFile = args[i + 1];
			} else if (args[i].equals("-p")) {
				path = args[i + 1];
			} else if (args[i].equals("-l")) {
				logFile = args[i + 1];
			} else if (args[i].equals("-h")) {
				hash = args[i + 1];
			}
		}
	}

	public static void writeFile(File file, String output) throws IOException {
		FileWriter fr = new FileWriter(file, true);
		fr.write(output + "\n");
		fr.close();

	}

	public static String readFile(File file) throws FileNotFoundException {
		Scanner myReader = new Scanner(file);
		String content = "";
		while (myReader.hasNextLine()) {
			String data = myReader.nextLine();
			content += data + "\n";
		}
		myReader.close();
		return content;
	}

	public static byte[] Encryption(String plainText, SecretKey secretKey) throws Exception {

		byte[] clean = plainText.getBytes();
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encrypted = cipher.doFinal(clean);

		return encrypted;

	}

	public static String decrypt(byte[] encryptedText, SecretKey secretKey) throws Exception {

		Cipher cipherDecrypt = Cipher.getInstance("AES");
		cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decrypted = cipherDecrypt.doFinal(encryptedText);
		return new String(decrypted);
	}

	public static void deleteFile(File file) throws FileNotFoundException {
		PrintWriter writer = new PrintWriter(file);
		writer.print("");
		writer.close();
	}

	public static String getMd5(String password) {
		try {

			MessageDigest md = MessageDigest.getInstance("MD5");

			byte[] messageDigest = md.digest(password.getBytes());

			BigInteger no = new BigInteger(1, messageDigest);

			String hashtext = no.toString(16);
			while (hashtext.length() < 32) {
				hashtext = "0" + hashtext;
			}
			return hashtext;
		}

		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static String getSHA(String password) {
		try {

			MessageDigest md = MessageDigest.getInstance("SHA-256");

			byte[] messageDigest = md.digest(password.getBytes());

			BigInteger no = new BigInteger(1, messageDigest);
			StringBuilder hexString = new StringBuilder(no.toString(16));
			while (hexString.length() < 32) {

				hexString.insert(0, '0');

			}
			return hexString.toString();
		}

		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

	}

	public static boolean findText(String searchingText, String searchedArea) {
		searchingText = searchingText.replaceAll("\\s+", "");
		searchedArea = searchedArea.replaceAll("\\s+", "");
		boolean isEqual = false;
		for (int i = 0; i < searchedArea.length() - searchingText.length() + 1; i++) {
			if (searchedArea.charAt(i) == searchingText.charAt(0)) {
				for (int j = 1; j < searchingText.length(); j++) {
					if (searchingText.charAt(j) == (searchedArea.charAt(i + j))) {
						isEqual = true;
					} else {
						isEqual = false;
						break;
					}
				}
				if (isEqual == true) {
					return true;
				}

			}
		}
		return false;
	}

	public static SecretKey stringToKey(String md5String) {
		byte[] decodedKey = Base64.getDecoder().decode(md5String);

		SecretKey AesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		return AesKey;
	}

	public static SecretKey keyGenerator() throws NoSuchAlgorithmException {
		SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
		return secretKey;

	}

	public static void encryptFile(File file, SecretKey secretKey) throws Exception {
		String contentOfFile = readFile(file);
		deleteFile(file);
		byte[] encryptByte = Encryption(contentOfFile, secretKey);
		String encodedString = Base64.getEncoder().encodeToString(encryptByte);
		writeFile(file, encodedString);

	}

	public static String decryptFile(File file, SecretKey secretKey) throws Exception {
		String contentOfFile = readFile(file).replaceAll("\\r|\\n", "");

		byte[] byteContent = Base64.getDecoder().decode(contentOfFile);
		String decryptText = decrypt(byteContent, secretKey);
		return decryptText;

	}
}