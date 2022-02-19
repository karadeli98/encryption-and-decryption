import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Server {
	static HashMap<Socket, Integer> clients = new HashMap<>();

	@SuppressWarnings("resource")
	public static void main(String[] args) throws Exception {

		// Delete contents of older file
		PrintWriter pw = new PrintWriter("log.txt");
		pw.close();
		try {
			ServerSocket server = new ServerSocket(8888);
			int counter = 0;
			System.out.println("Server Started ...");
			writeFile("Server Started ...");
			

			// Create Initial Vector for aes and des methods
			IvParameterSpec aesIv = generateInitialVector(16);
			IvParameterSpec desIv = generateInitialVector(8);

			// Create secret key for aes and des
			SecretKey secretKeyAes = keyGenerator("AES");
			SecretKey secretKeyDes = keyGenerator("DES");

			// Store secret key in file
			WriteObjectToFile(secretKeyAes, "secretKeyAes");
			WriteObjectToFile(secretKeyDes, "secretKeyDes");

			writeFile("AES inital vector is :" + Base64.getEncoder().encodeToString(aesIv.getIV()));

			writeFile("DES inital vector is :" + Base64.getEncoder().encodeToString(desIv.getIV()));

			writeFile("AES random key is :" + Base64.getEncoder().encodeToString(secretKeyAes.getEncoded()));

			writeFile("DES random key is :" + Base64.getEncoder().encodeToString(secretKeyDes.getEncoded()));

			while (true) {
				counter++;
				Socket serverClient = server.accept(); // server accept the client connection request
				writeFile(" >> " + "Client No:" + counter + " started!");
				ServerClientThread sct = new ServerClientThread(serverClient, counter); // send the request to a
				clients.put(serverClient, counter);
				sct.start();
			}

		} catch (Exception e) {
			System.out.println(e);
			writeFile(e.toString());
		}

	}

	public static SecretKey keyGenerator(String mode) throws NoSuchAlgorithmException {
		SecretKey secretKey = KeyGenerator.getInstance(mode).generateKey();
		return secretKey;

	}

	public static IvParameterSpec generateInitialVector(int ivSize) throws FileNotFoundException, IOException {
		String ivFile = "";
		byte[] iv = new byte[ivSize];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		if (ivSize == 16) {
			ivFile = "ivFileAes";
		} else {
			ivFile = "ivFileDes";
		}

		try (FileOutputStream out = new FileOutputStream(ivFile)) {
			out.write(iv);
		}

		return ivParameterSpec;
	}

	public static void WriteObjectToFile(Object serObj, String filepath) {

		try {

			FileOutputStream fileOut = new FileOutputStream(filepath);
			ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
			objectOut.writeObject(serObj);
			objectOut.close();

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static void writeFile(String output) throws IOException {
		File file = new File("log.txt");
		FileWriter fr = new FileWriter(file, true);
		fr.write(output + "\n");
		fr.close();

	}
}

class ServerClientThread extends Thread {
	Socket serverClient;
	int clientNo;

	ServerClientThread(Socket inSocket, int counter) {
		serverClient = inSocket;
		clientNo = counter;
	}

	@SuppressWarnings("rawtypes")
	public void run() {
		try {
			DataInputStream inStream = new DataInputStream(serverClient.getInputStream());
			DataOutputStream outStream = new DataOutputStream(serverClient.getOutputStream());
			String[] message = { "", "" };
			while (!message[1].equals("quitServer")) {
				message = inStream.readUTF().split(" ");
				if (message[1].equals("quitServer")) {
					Server.clients.remove(serverClient);
				} else {

					Server.writeFile(message[0] + " > " + message[1]);
				}

				for (Map.Entry object : Server.clients.entrySet()) {

					Socket client = (Socket) object.getKey();
					DataOutputStream outStream1 = new DataOutputStream(client.getOutputStream());
					outStream1.writeUTF(message[0] + " " + message[1]);
					outStream1.flush();
				}

				outStream.flush();

			}
			inStream.close();
			outStream.close();
			serverClient.close();

		} catch (Exception ex) {
			System.out.println(ex);
		} finally {
			try {
				Server.writeFile("Client -" + clientNo + " exit!! ");
			} catch (IOException ex) {
				Logger.getLogger(ServerClientThread.class.getName()).log(Level.SEVERE, null, ex);
			}
		}
	}

}