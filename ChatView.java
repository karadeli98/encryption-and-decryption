import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JRadioButton;
import javax.swing.JPanel;
import javax.swing.AbstractButton;
import javax.swing.ButtonGroup;
import javax.swing.JButton;

import java.awt.Label;
import java.awt.event.ActionListener;
import javax.swing.JTextArea;
import java.awt.TextField;
import javax.swing.border.TitledBorder;

import java.util.Enumeration;

import java.awt.event.ActionEvent;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JLabel;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class ChatView implements ActionListener {

	private ButtonGroup methodButtonGroup = new ButtonGroup();
	private ButtonGroup modeButtonGroup = new ButtonGroup();
	private ButtonGroup connectGroup = new ButtonGroup();
	private JFrame frame;
	private JButton connectButton = new JButton("Connect");

	private JTextArea textArea = new JTextArea();
	private JButton encryptButton = new JButton("Encrpt");
	private String userName = "";
	private JButton disconnectButton = new JButton("Disconnect");
	private JPanel modePanel = new JPanel();
	private JButton sendButton = new JButton("Send");
	private String originalText = "";
	private TextField originalTextField = new TextField();
	private JLabel connectJLabel = new JLabel("Not connected");
	private TextField cryptedText = new TextField();
	private JRadioButton ofbButton = new JRadioButton("OFB");
	private JRadioButton cbcButton = new JRadioButton("CBC");
	private JRadioButton desButton = new JRadioButton("DES");
	private JRadioButton aesButton = new JRadioButton("AES");

	private InputStream inputStream;
	private OutputStream outputStream;
	private DataOutputStream outData;
	private DataInputStream inData;

	private String serverIP;
	private Socket connection;
	private int port = 8888;
	private boolean option = true;

	private String encMode;
	private String encMethod;
	private static IvParameterSpec aesIv = null;
	private static IvParameterSpec desIv = null;
	private static SecretKey secretKeyAes = null;
	private static SecretKey secretKeyDes = null;

	public ChatView(String s) {
		initialize();
		this.frame.setVisible(true);
		serverIP = s;
	}

	/**
	 * Initialize the contents of the frame.
	 */

	private void initialize() {

		frame = new JFrame("Crypto Messenger");
		frame.setBounds(100, 100, 669, 768);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JPanel panel_1 = new JPanel();
		panel_1.setBounds(0, 20, 650, 114);
		frame.getContentPane().add(panel_1);
		panel_1.setLayout(null);

		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(null, "JPanel title", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		panel_2.setBounds(-6, -15, 662, 135);
		panel_1.add(panel_2);
		panel_2.setLayout(null);

		JPanel panel = new JPanel();
		panel.setBounds(6, 15, 650, 114);
		panel_2.add(panel);
		panel.setLayout(null);

		connectButton.setBounds(69, 62, 85, 21);
		panel.add(connectButton);
		connectGroup.add(connectButton);
		connectButton.addActionListener(this);

		disconnectButton.setEnabled(false);
		disconnectButton.setBounds(164, 62, 113, 21);
		panel.add(disconnectButton);
		connectGroup.add(disconnectButton);
		disconnectButton.addActionListener(this);

		JPanel methodPanel = new JPanel();

		methodPanel.setBorder(new TitledBorder(null, "Method", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		methodPanel.setBounds(302, 10, 123, 82);
		panel.add(methodPanel);
		methodPanel.setLayout(null);

		aesButton.setSelected(true);
		aesButton.setBounds(6, 55, 51, 21);
		methodPanel.add(aesButton);
		modeButtonGroup.add(aesButton);
		aesButton.addActionListener(this);

		desButton.setBounds(66, 55, 51, 21);
		methodPanel.add(desButton);
		modeButtonGroup.add(desButton);
		desButton.addActionListener(this);

		modePanel.setBorder(new TitledBorder(null, "Mode", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		modePanel.setBounds(472, 10, 127, 82);
		panel.add(modePanel);
		modePanel.setLayout(null);

		cbcButton.setSelected(true);
		cbcButton.setBounds(6, 55, 51, 21);
		modePanel.add(cbcButton);
		methodButtonGroup.add(cbcButton);
		cbcButton.addActionListener(this);

		ofbButton.setBounds(70, 55, 51, 21);
		modePanel.add(ofbButton);
		methodButtonGroup.add(ofbButton);
		ofbButton.addActionListener(this);

		textArea.setBounds(0, 139, 650, 411);
		frame.getContentPane().add(textArea);

		JPanel textPanel = new JPanel();
		textPanel.setBorder(new TitledBorder(null, "Text", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		textPanel.setBounds(4, 556, 217, 142);
		frame.getContentPane().add(textPanel);
		textPanel.setLayout(null);

		originalTextField.setBounds(6, 22, 205, 114);
		textPanel.add(originalTextField);

		JPanel cryptedTextPanel = new JPanel();
		cryptedTextPanel
				.setBorder(new TitledBorder(null, "Crypted Text", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		cryptedTextPanel.setBounds(224, 556, 237, 142);
		frame.getContentPane().add(cryptedTextPanel);
		cryptedTextPanel.setLayout(null);

		cryptedText.setBounds(10, 21, 217, 111);
		cryptedTextPanel.add(cryptedText);

		encryptButton.setBounds(477, 623, 85, 21);
		frame.getContentPane().add(encryptButton);
		encryptButton.addActionListener(this);

		sendButton.setEnabled(false);
		sendButton.setBounds(561, 623, 82, 21);
		frame.getContentPane().add(sendButton);
		sendButton.addActionListener(this);

		Label label = new Label("Server");
		label.setBounds(0, 0, 650, 21);
		frame.getContentPane().add(label);

		connectJLabel.setBounds(0, 718, 223, 13);
		frame.getContentPane().add(connectJLabel);

	}

	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
		this.setEncMode(getSelectedButtonText(modeButtonGroup).trim());
		this.setEncMethod(getSelectedButtonText(methodButtonGroup).trim());
		if (e.getSource() == connectButton) {
			dialogBox();
			disconnectButton.setEnabled(true);
			connectButton.setEnabled(false);
			connectJLabel.setText("Connected: " + userName);
			startRunning();

		} else if (e.getSource() == encryptButton) {

			sendButton.setEnabled(true);
			originalText = originalTextField.getText();
			byte[] originalTextByte = null;
			if (encMode.equals("AES")) {
				try {
					originalTextByte = Encryption(originalText, this.getSecretKeyAes());

				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			} else {
				try {
					originalTextByte = Encryption(originalText, this.getSecretKeyDes());
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
			originalText = Base64.getEncoder().encodeToString(originalTextByte);
			cryptedText.setText(originalText);

		} else if (e.getSource() == sendButton) {
			String data = userName + " " + originalText;
			sendData(data);
			originalTextField.setText("");
			// cryptedText.setText("");

		} else if (e.getSource() == disconnectButton) {
			sendData(userName + " " + "quitServer");
			connectButton.setEnabled(true);
			disconnectButton.setEnabled(false);
			connectJLabel.setText("Not connected");
		}

	}

	public void dialogBox() {
		String s = (String) JOptionPane.showInputDialog(frame, "Enter user name:", "Input", JOptionPane.PLAIN_MESSAGE);
		if (s.length() > 0) {
			this.userName = s;
		}
		return;

	}

	public String getSelectedButtonText(ButtonGroup buttonGroup) {
		for (Enumeration<AbstractButton> buttons = buttonGroup.getElements(); buttons.hasMoreElements();) {
			AbstractButton button = buttons.nextElement();

			if (button.isSelected()) {
				return button.getText();
			}
		}

		return null;
	}

	public void startRunning() {
		try {
			connection = new Socket(InetAddress.getByName(serverIP), port);
			Thread th1 = new Thread(new Runnable() {
				@Override
				public void run() {
					while (option) {
						listenData();
					}
				}

			});
			th1.start();

		} catch (IOException ex) {
			Logger.getLogger(ChatView.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	public void sendData(String data) {
		try {
			String[] pieces = data.split(" ");
			outputStream = connection.getOutputStream();
			outData = new DataOutputStream(outputStream);
			outData.writeUTF(data);
			outData.flush();
			if (pieces[1].equals("quitServer")) {
				closeConnection();
			}

		} catch (IOException ex) {
			Logger.getLogger(ChatView.class.getName()).log(Level.SEVERE, null, ex);
		}

	}

	public void closeConnection() {
		try {
			option = false;
			outData.close();
			inData.close();
			connection.close();
			// this.frame.dispose();

		} catch (IOException ex) {
			Logger.getLogger(ChatView.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	public void listenData() {

		try {
			inputStream = connection.getInputStream();
			inData = new DataInputStream(inputStream);
			String[] input = inData.readUTF().split(" ");
			if (input[1].equals("quitServer")) {
				textArea.append(input[0] + " closed the server connection." + "\n");

			} else {
				String encryptedMessage = input[1];
				String userName = input[0];
				textArea.append(encryptedMessage + "\n");
				textArea.append(userName + "> ");
				String output = "";
				if (encMode.equals("AES")) {
					try {

						output = decrypt(Base64.getDecoder().decode(encryptedMessage), this.getSecretKeyAes());

					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				} else {
					try {
						output = decrypt(Base64.getDecoder().decode(encryptedMessage), this.getSecretKeyDes());
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}

				textArea.append(output + "\n");
			}

		} catch (IOException ex) {
			System.out.print(ex);
		}
	}

	public byte[] Encryption(String plainText, SecretKey secretKey) throws Exception {

		byte[] clean = plainText.getBytes();
		byte[] iv = null;
		if (this.getEncMode().equals("AES")) {
			iv = Files.readAllBytes(Paths.get("ivFileAes"));

		} else {
			iv = Files.readAllBytes(Paths.get("ivFileDes"));

		}
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		String instance = this.getEncMode() + "/" + this.getEncMethod() + "/PKCS5Padding";
		Cipher cipher = Cipher.getInstance(instance);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
		byte[] encrypted = cipher.doFinal(clean);

		return encrypted;

	}

	public String decrypt(byte[] encryptedText, SecretKey secretKey) throws Exception {

		byte[] iv = null;
		// Extract IV.
		if (this.getEncMode().equals("AES")) {
			iv = Files.readAllBytes(Paths.get("ivFileAes"));

		} else {
			iv = Files.readAllBytes(Paths.get("ivFileDes"));

		}
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

		String instance = this.getEncMode() + "/" + this.getEncMethod() + "/PKCS5Padding";
		Cipher cipherDecrypt = Cipher.getInstance(instance);
		cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
		byte[] decrypted = cipherDecrypt.doFinal(encryptedText);

		return new String(decrypted);
	}

	public SecretKey getSecretKeyDes() {
		return secretKeyDes;
	}

	public void setSecretKeyDes(SecretKey secretKeyDes) {
		ChatView.secretKeyDes = secretKeyDes;
	}

	public SecretKey getSecretKeyAes() {
		return secretKeyAes;
	}

	public void setSecretKeyAes(SecretKey secretKeyAes) {
		ChatView.secretKeyAes = secretKeyAes;
	}

	public static IvParameterSpec getDesIv() {
		return desIv;
	}

	public static void setDesIv(IvParameterSpec desIv) {
		ChatView.desIv = desIv;
	}

	public static IvParameterSpec getAesIv() {
		return aesIv;
	}

	public static void setAesIv(IvParameterSpec aesIv) {
		ChatView.aesIv = aesIv;
	}

	public String getEncMethod() {
		return encMethod;
	}

	public void setEncMethod(String encMethod) {
		this.encMethod = encMethod;
	}

	public String getEncMode() {
		return encMode;
	}

	public void setEncMode(String encMode) {
		this.encMode = encMode;
	}

}
