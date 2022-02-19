import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import javax.crypto.SecretKey;

public class Client {

	@SuppressWarnings({ "unused", "resource" })
	public static void main(String[] args) throws IOException, ClassNotFoundException {

		//Read secret key files which created in Server
		FileInputStream aesKeyFile = new FileInputStream(new File("secretKeyAes"));
		FileInputStream desKeyFile = new FileInputStream(new File("secretKeyDes"));
		ObjectInputStream aesKey = new ObjectInputStream(aesKeyFile);
		ObjectInputStream desKey = new ObjectInputStream(desKeyFile);

		
		SecretKey aesKey2 = (SecretKey) aesKey.readObject();
		SecretKey desKey2 = (SecretKey) desKey.readObject();

		ChatView s = new ChatView("127.0.0.1");
		s.setSecretKeyAes(aesKey2);
		s.setSecretKeyDes(desKey2);

	}
}
