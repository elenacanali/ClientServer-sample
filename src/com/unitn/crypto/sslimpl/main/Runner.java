package com.unitn.crypto.sslimpl.main;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import com.unitn.crypto.sslimpl.client.Client;
import com.unitn.crypto.sslimpl.server.Server;

public class Runner {

	public static void main(String[] args) {
       // set look and feel to the system look and feel
       try {
           UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
       } catch (Exception ex) {
           ex.printStackTrace();
       }
        
       SwingUtilities.invokeLater(new Runnable() {
           @Override
           public void run() {
               new Gui().setVisible(true);
           }
       });
		//Gui gui = new Gui();
//		Server server = new Server();
//		Client client = new Client();
//		// create handshake
//		client.createHandshake();
//		// client choose proper KA and generate symmetric key
//		client.generateSymmetricKey();
//		// server read handshake
//		server.readHandshake();
//		// server choose proper KA and generate symmetric key
//		server.generateSymmetricKey();
//		server.sendMessage("Server to client first message");
//		System.out.println(client.readMessage());
//		client.sendMessage("Client to server first message");
//		System.out.println(server.readMessage());
//		server.sendMessage("Server to client second message");
//		System.out.println(client.readMessage());
//		client.requestChangeCipher();
//		System.out.println(server.readMessage());
//		server.sendMessage("Server to client first fart");
//		System.out.println(client.readMessage());
//		client.sendMessage("Client to server first fart");
//		System.out.println(server.readMessage());
//		server.sendMessage("Server to client second fart");
//		System.out.println(client.readMessage());
//		System.out.println("Done");
	}

}
