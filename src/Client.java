import javax.crypto.SecretKey;
import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class Client {

    private JTextArea messageArea;
    private JTextArea monitorArea;
    private JTextField inputField;
    private SecretKey logKey;
    private Set<String> usedNonces = new HashSet<>();
    private KeyPair clientKeyPair;
    private DataOutputStream out;

    public static void main(String[] args) throws Exception {
        new Client().start();
    }

    public void start() throws Exception {
        clientKeyPair = CryptoUtils.generateRSAKeyPair();
        logKey = CryptoUtils.generateAESKey();

        JFrame frame = new JFrame("ChatWindow - Client");
        messageArea = new JTextArea(10,50); messageArea.setEditable(false);
        monitorArea = new JTextArea(10,50); monitorArea.setEditable(false);
        inputField = new JTextField(40); JButton sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendMessage());

        JPanel bottom = new JPanel(); bottom.add(inputField); bottom.add(sendButton);
        frame.setLayout(new BorderLayout());
        frame.add(new JScrollPane(messageArea), BorderLayout.NORTH);
        frame.add(new JScrollPane(monitorArea), BorderLayout.CENTER);
        frame.add(bottom, BorderLayout.SOUTH);
        frame.pack(); frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); frame.setVisible(true);

        new Thread(this::connectToServer).start();
    }

    private void connectToServer(){
        try {
            char[] password = "password".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream("C:\\Users\\iamra\\Downloads\\CCS\\CCS\\src\\clientkeystore.jks"), password);


            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password);

            SSLContext ctx = SSLContext.getInstance("TLSv1.3");
            ctx.init(kmf.getKeyManagers(), null, null);

            SSLSocketFactory factory = ctx.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 8443);

            out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            logEvent("Connected to server.");

            while(true){
                String received = in.readUTF();
                String[] parts = received.split("\\|",3);
                if(parts.length<3) continue;
                String nonce = parts[0]; String msg = parts[1]; byte[] sig = Base64.getDecoder().decode(parts[2]);

                if(usedNonces.contains(nonce)) continue;
                usedNonces.add(nonce);

                if(!CryptoUtils.verify(clientKeyPair.getPublic(), msg.getBytes(), sig)) continue;

                messageArea.append("Server: "+msg+"\n");
                logEvent("Received: "+msg);
            }

        } catch(Exception e){ logEvent("Disconnected from server."); }
    }

    private void sendMessage(){
        try{
            String msg = inputField.getText(); if(msg.isEmpty()) return;
            String nonce = Base64.getEncoder().encodeToString(CryptoUtils.generateNonce());
            byte[] sig = CryptoUtils.sign(clientKeyPair.getPrivate(), msg.getBytes());
            String packet = nonce+"|"+msg+"|"+Base64.getEncoder().encodeToString(sig);

            out.writeUTF(packet); out.flush();
            messageArea.append("You: "+msg+"\n"); logEvent("Sent: "+msg); inputField.setText("");

        } catch(Exception e){ logEvent("Failed to send message."); }
    }

    private void logEvent(String event){
        monitorArea.append(event+"\n");
        try { CryptoUtils.writeEncryptedLog(Paths.get("client_logs.enc"), event+"\n", logKey); }
        catch(Exception e){ e.printStackTrace(); }
    }
}
