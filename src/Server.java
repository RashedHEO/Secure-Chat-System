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

public class Server {

    private JTextArea messageArea;
    private JTextArea monitorArea;
    private SecretKey logKey;
    private Set<String> usedNonces = new HashSet<>();
    private KeyPair serverKeyPair;

    public static void main(String[] args) throws Exception {
        new Server().start();
    }

    public void start() throws Exception {
        // توليد المفاتيح
        serverKeyPair = CryptoUtils.generateRSAKeyPair();
        logKey = CryptoUtils.generateAESKey();

        // واجهة GUI باسم ChatWindow
        JFrame frame = new JFrame("ChatWindow - Server");
        messageArea = new JTextArea(10, 50); messageArea.setEditable(false);
        monitorArea = new JTextArea(10, 50); monitorArea.setEditable(false);
        frame.setLayout(new BorderLayout());
        frame.add(new JScrollPane(messageArea), BorderLayout.NORTH);
        frame.add(new JScrollPane(monitorArea), BorderLayout.CENTER);
        frame.pack(); frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); frame.setVisible(true);

        new Thread(this::startServer).start();
    }

    private void startServer() {
        try {
            char[] password = "password".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream("C:\\Users\\iamra\\Downloads\\CCS\\CCS\\src\\serverkeystore.jks"), password);


            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password);

            SSLContext ctx = SSLContext.getInstance("TLSv1.3");
            ctx.init(kmf.getKeyManagers(), null, null);

            SSLServerSocketFactory factory = ctx.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(8443);
            logEvent("Server started on port 8443");

            while(true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                logEvent("Client connected: " + clientSocket.getInetAddress());
                new Thread(() -> handleClient(clientSocket)).start();
            }

        } catch (Exception e) { e.printStackTrace(); }
    }

    private void handleClient(SSLSocket clientSocket) {
        try(DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())) {

            while(true) {
                String received = in.readUTF();
                String[] parts = received.split("\\|", 3);
                if(parts.length<3) continue;

                String nonce = parts[0]; String msg = parts[1];
                byte[] sig = Base64.getDecoder().decode(parts[2]);

                if(usedNonces.contains(nonce)) { logEvent("Replay detected."); continue; }
                usedNonces.add(nonce);

                if(!CryptoUtils.verify(serverKeyPair.getPublic(), msg.getBytes(), sig)) {
                    logEvent("Invalid signature. Message discarded."); continue;
                }

                messageArea.append("Client: " + msg + "\n");
                logEvent("Received: " + msg);

                String responseMsg = "Server received: " + msg;
                String responseNonce = Base64.getEncoder().encodeToString(CryptoUtils.generateNonce());
                byte[] responseSig = CryptoUtils.sign(serverKeyPair.getPrivate(), responseMsg.getBytes());
                String response = responseNonce+"|"+responseMsg+"|"+Base64.getEncoder().encodeToString(responseSig);

                out.writeUTF(response); out.flush();
                messageArea.append("Server: " + responseMsg + "\n");
                logEvent("Sent: " + responseMsg);
            }

        } catch(Exception e) { logEvent("Client disconnected."); }
    }

    private void logEvent(String event){
        monitorArea.append(event + "\n");
        try { CryptoUtils.writeEncryptedLog(Paths.get("server_logs.enc"), event + "\n", logKey); }
        catch(Exception e){ e.printStackTrace(); }
    }
}
