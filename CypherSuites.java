package sslexample;

import java.io.IOException;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class CypherSuites {
  public static void main(String[] args) {
    String host = args[0];
    int port = Integer.parseInt(args[1]);

    try {
      System.out.println("Locating socket factory for SSL...");
      SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

      System.out.println("Creating secure socket to " + host + ":" + port);
      SSLSocket socket = (SSLSocket) factory.createSocket(host, port);

      System.out.println("Enabling all available cipher suites...");
      String[] suites = socket.getSupportedCipherSuites();
      socket.setEnabledCipherSuites(suites);

      System.out.println("Registering a handshake listener...");
      socket.addHandshakeCompletedListener(new MyHandshakeListener());

      System.out.println("Starting handshaking...");
      socket.startHandshake();

      System.out.println("Just connected to " + socket.getRemoteSocketAddress());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}

class MyHandshakeListener implements HandshakeCompletedListener {
  public void handshakeCompleted(HandshakeCompletedEvent e) {
    System.out.println("Handshake succesful!");
    System.out.println("Using cipher suite: " + e.getCipherSuite());
  }
}
