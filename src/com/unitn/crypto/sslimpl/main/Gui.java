package com.unitn.crypto.sslimpl.main;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import com.unitn.crypto.sslimpl.client.Client;
import com.unitn.crypto.sslimpl.server.Server;

public class Gui extends JFrame implements ActionListener, ItemListener {
    
   private Server server = null;
   private Client client = null;
   private JLabel labelServerInit = new JLabel("Initialize server (create file and sign): ");
   private JLabel labelClientInit = new JLabel("Initialize client (read server file and confirm signature): ");
   //private JTextField textUsername = new JTextField(20);
   private JButton buttonServerInit = new JButton("Server Init");
   private JButton buttonClientInit = new JButton("Client Init");
   private JButton restartButton = new JButton("Restart");
   private JPanel lastJPanel = null;
   private JPanel cipherServerPanel = null;
   private JPanel cipherClientPanel = null;
   private final String[] choices = { "SHA1withDSA", "SHA1withRSA", "SHA256withRSA"};
   private final JComboBox<String> cbDS = new JComboBox<String>(choices);
   private final String[] kaChoices = { "DiffieHellman" };
   private final JComboBox<String> cbKA = new JComboBox<String>(kaChoices);
   
   
   // second gui
   private JLabel serverLabel = new JLabel("Server");
   private JLabel clientLabel = new JLabel("Client");
   private JLabel selectedCipherLabel = new JLabel("Selected Cipher: ");
   private JLabel selectedCipherValue = new JLabel("");
   private JButton sendClientText = new JButton("Send text to server");
   private JTextArea clientText = new JTextArea();
   private JButton sendServerText = new JButton("Send text to client");
   private JTextArea serverText = new JTextArea();
   private String selectedCipher;
   private JButton changeCipher = new JButton("Change cipher agreement with a random cipher");
   
   private List<String> clientCiphers = new ArrayList<String>();
   private List<String> serverCiphers = new ArrayList<String>();
   
   public Gui() {
       super("Server Client Demo");
       this.startGUI();
       
      pack();
      setLocationRelativeTo(null);
   }
   
   public void startGUI(){
	  Container contentPane = this.getContentPane();
	  contentPane.removeAll();
      this.lastJPanel = this.firstGUI();
      contentPane.add(this.lastJPanel);
      validate();
      setVisible(true);
   }
   
   public void addAlertToPanel(String message){
       Container contentPane = this.getContentPane();
       contentPane.removeAll();
       JLabel newLabel = new JLabel(message);
       newLabel.setForeground(Color.RED);
       JPanel newPanel= new JPanel(new GridBagLayout());
       GridBagConstraints constraints = new GridBagConstraints();
       constraints.anchor = GridBagConstraints.WEST;
       constraints.insets = new Insets(10, 10, 10, 10);
       constraints.gridx = 0;
       constraints.gridy = 2;
       constraints.gridwidth = 2;
       constraints.anchor = GridBagConstraints.CENTER; 
       newPanel.add(newLabel,constraints);
       constraints.gridy = 4;
       this.restartButton.addActionListener(this);
       this.restartButton.setActionCommand("restartButton");
       newPanel.add(this.restartButton, constraints);
       contentPane.add(newPanel);
       validate();
       setVisible(true);
   }
   
   public JPanel firstGUI(){
       // create a new panel with GridBagLayout manager
       JPanel newPanel = new JPanel(new GridBagLayout());
        
       GridBagConstraints constraints = new GridBagConstraints();
       constraints.anchor = GridBagConstraints.WEST;
       constraints.insets = new Insets(10, 10, 10, 10);
        
       // add components to the panel
       constraints.gridx = 0;
       constraints.gridy = 0;     
       newPanel.add(this.labelServerInit, constraints);

       // digital signature algo
       constraints.gridx = 0;
       constraints.gridy = 2;
       constraints.gridwidth = 2;
       JLabel dsLabel = new JLabel("DS algo");
       newPanel.add(dsLabel, constraints);
       constraints.gridx = 1;
       constraints.gridy = 2;
       constraints.gridwidth = 2;
       this.cbDS.setVisible(true);
       newPanel.add(this.cbDS, constraints);
       
       // KA algo
       constraints.gridx = 0;
       constraints.gridy = 4;
       constraints.gridwidth = 2;
       JLabel kaLabel = new JLabel("KA algo");
       newPanel.add(kaLabel, constraints);
       constraints.gridx = 1;
       constraints.gridy = 4;
       constraints.gridwidth = 2;
       this.cbKA.setVisible(true);
       newPanel.add(this.cbKA, constraints);
       
       // ciphers
       JPanel cipherServerPanel = new JPanel(new GridLayout(0, 2));
       
       JCheckBox cb1 = new JCheckBox("DES/CBC/NoPadding");
       cb1.addItemListener(this);
       cb1.setActionCommand("server");
       cipherServerPanel.add(cb1);
       JCheckBox cb2 = new JCheckBox("DES/CBC/PKCS5Padding");
       cb2.addItemListener(this);
       cb2.setActionCommand("server");
       cipherServerPanel.add(cb2);
       JCheckBox cb3 = new JCheckBox("DES/ECB/NoPadding");
       cb3.addItemListener(this);
       cb3.setActionCommand("server");
       cipherServerPanel.add(cb3);
       JCheckBox cb4 = new JCheckBox("DES/ECB/PKCS5Padding");
       cb4.addItemListener(this);
       cb4.setActionCommand("server");
       cipherServerPanel.add(cb4);
       JCheckBox cb5 = new JCheckBox("DESede/CBC/NoPadding");
       cb5.addItemListener(this);
       cb5.setActionCommand("server");
       cipherServerPanel.add(cb5);
       JCheckBox cb6 = new JCheckBox("DESede/CBC/PKCS5Padding");
       cb6.addItemListener(this);
       cb6.setActionCommand("server");
       cipherServerPanel.add(cb6);
       JCheckBox cb7 = new JCheckBox("DESede/ECB/NoPadding");
       cb7.addItemListener(this);
       cb7.setActionCommand("server");
       cipherServerPanel.add(cb7);
       JCheckBox cb8 = new JCheckBox("DESede/ECB/PKCS5Padding");
       cb8.addItemListener(this);
       cb8.setActionCommand("server");
       cipherServerPanel.add(cb8);
       
       
       this.cipherServerPanel = cipherServerPanel;
       
       constraints.gridx = 0;
       constraints.gridy = 6;
       constraints.gridwidth = 2;
       constraints.anchor = GridBagConstraints.CENTER; 
       newPanel.add(cipherServerPanel, constraints);
       
       // add listener
       this.buttonServerInit.addActionListener(this);
       this.buttonServerInit.setActionCommand("buttonServerInit");
       
       constraints.gridx = 0;
       constraints.gridy = 8;
       constraints.gridwidth = 2;
       constraints.anchor = GridBagConstraints.CENTER;
       newPanel.add(this.buttonServerInit, constraints);
        
       constraints.gridx = 0;
       constraints.gridy = 10;     
       newPanel.add(this.labelClientInit, constraints);
       
       JPanel cipherClientPanel = new JPanel(new GridLayout(0, 2));
       JCheckBox cp1 = new JCheckBox("DES/CBC/NoPadding");
       cp1.addItemListener(this);
       cp1.setActionCommand("client");
       cipherClientPanel.add(cp1);
       JCheckBox cp2 = new JCheckBox("DES/CBC/PKCS5Padding");
       cp2.addItemListener(this);
       cp2.setActionCommand("client");
       cipherClientPanel.add(cp2);
       JCheckBox cp3 = new JCheckBox("DES/ECB/NoPadding");
       cp3.addItemListener(this);
       cp3.setActionCommand("client");
       cipherClientPanel.add(cp3);
       JCheckBox cp4 = new JCheckBox("DES/ECB/PKCS5Padding");
       cp4.addItemListener(this);
       cp4.setActionCommand("client");
       cipherClientPanel.add(cp4);
       JCheckBox cp5 = new JCheckBox("DESede/CBC/NoPadding");
       cp5.addItemListener(this);
       cp5.setActionCommand("client");
       cipherClientPanel.add(cp5);
       JCheckBox cp6 = new JCheckBox("DESede/CBC/PKCS5Padding");
       cp6.addItemListener(this);
       cp6.setActionCommand("client");
       cipherClientPanel.add(cp6);
       JCheckBox cp7 = new JCheckBox("DESede/ECB/NoPadding");
       cp7.addItemListener(this);
       cp7.setActionCommand("client");
       cipherClientPanel.add(cp7);
       JCheckBox cp8 = new JCheckBox("DESede/ECB/PKCS5Padding");
       cp8.addItemListener(this);
       cp8.setActionCommand("client");
       cipherClientPanel.add(cp8);
       this.cipherClientPanel = cipherClientPanel;
       constraints.gridx = 0;
       constraints.gridy = 12;
       constraints.gridwidth = 2;
       constraints.anchor = GridBagConstraints.CENTER;
       newPanel.add(cipherClientPanel, constraints);
       
       // add listener
       this.buttonClientInit.addActionListener(this);
       this.buttonClientInit.setActionCommand("buttonClientInit");
       constraints.gridx = 0;
       constraints.gridy = 14;
       constraints.gridwidth = 2;
       constraints.anchor = GridBagConstraints.CENTER; 
       newPanel.add(this.buttonClientInit, constraints);
        
       // set border for the panel
       newPanel.setBorder(BorderFactory.createTitledBorder(
               BorderFactory.createEtchedBorder(), "Init Panel"));
       
       return newPanel;
   }

	@Override
	public void actionPerformed(ActionEvent ae) {
		String action = ae.getActionCommand();
        if (action.equals("buttonServerInit")) {
            try {
            	String dsAlgo = (String)this.cbDS.getSelectedItem();
            	String ksAlgo = (String)this.cbKA.getSelectedItem();
				this.server = new Server(dsAlgo, ksAlgo, this.serverCiphers);
			} catch (IOException e) {
				this.addAlertToPanel("Something went wrong in the server client agreement. Try again");
				e.printStackTrace();
			}
        }
        else if(action.equals("buttonClientInit")) {
        	boolean success = false;
        	try {
				this.client = new Client(this.clientCiphers);
				this.client.createHandshake();
				this.client.generateSymmetricKey();
				this.server.readHandshake();
				this.selectedCipher = this.server.generateSymmetricKey();
				success = true;
			} catch (NoSuchAlgorithmException e) {
				this.addAlertToPanel("Something went wrong in the server client agreement. Try again");
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				this.addAlertToPanel("Something went wrong in the server client agreement. Try again");
				e.printStackTrace();
			} catch (IOException e) {
				this.addAlertToPanel("Something went wrong in the server client agreement. Try again");
				e.printStackTrace();
			} catch (Exception e) {
				this.addAlertToPanel("Something went wrong in the server client agreement. Try again");
				e.printStackTrace();
			}
        	if(success){
        		this.updatePanelToExchangeMessages();
        	}
        }
        else if(action.equals("sendServerText")) {
        	String plaintext = this.serverText.getText();
        	try {
				this.server.sendMessage(plaintext);
				String received = this.client.readMessage();
				this.clientText.setText(received);
			} catch (IOException e) {
				this.addAlertToPanel("Something went wrong in the server sendinga message");
				e.printStackTrace();
			}
        }
        else if(action.equals("sendClientText")) {
        	String plaintext = this.clientText.getText();
        	try {
				this.client.sendMessage(plaintext);
				String received = this.server.readMessage();
				this.serverText.setText(received);
			} catch (IOException e) {
				this.addAlertToPanel("Something went wrong in the client sendinga message");
				e.printStackTrace();
			} catch (Exception e) {
				this.addAlertToPanel("Something went wrong in the client sendinga message");
				e.printStackTrace();
			}
        }
        else if(action.equals("changeCipher")) {
        	boolean success = false;
        	try {
				client.requestChangeCipher();
				this.selectedCipher = server.readMessage();
				success = true;
			} catch (IOException e) {
				this.addAlertToPanel("Something went wrong in the client asking to change cipher");
				e.printStackTrace();
			} catch (Exception e) {
				this.addAlertToPanel("Something went wrong in the server agreeing on the new cipher");
				e.printStackTrace();
			}
        	if(success){
        		this.selectedCipherValue.setText(this.selectedCipher);
        		this.lastJPanel.repaint();
        		
        	}
        }
        else if(action.equals("restartButton")) {
        	this.startGUI();
        } 

	}

	private void updatePanelToExchangeMessages() {
		Container cont = this.getContentPane();
		cont.removeAll();
        JPanel newPanel = new JPanel(new GridLayout(0, 2, 5, 5));
        newPanel.add(this.selectedCipherLabel);
        this.selectedCipherValue.setText(this.selectedCipher);
        newPanel.add(this.selectedCipherValue);
        newPanel.add(this.serverLabel);
        newPanel.add(this.clientLabel);
        newPanel.add(this.serverText);
        newPanel.add(this.clientText);
        this.sendServerText.addActionListener(this);
        this.sendServerText.setActionCommand("sendServerText");
        newPanel.add(this.sendServerText);
        this.sendClientText.addActionListener(this);
        this.sendClientText.setActionCommand("sendClientText");
        newPanel.add(this.sendClientText);
        this.changeCipher.addActionListener(this);
        this.changeCipher.setActionCommand("changeCipher");
        newPanel.add(this.changeCipher);
        cont.add(newPanel);
        validate();
        setVisible(true);
	}

	@Override
	public void itemStateChanged(ItemEvent e) {
		JCheckBox cb = (JCheckBox)e.getItem();
		String cipher = cb.getText();
		String action = cb.getActionCommand();
		if (action.equals("client")) {
			if(cb.isSelected())
				clientCiphers.add(cipher);
			else 
				clientCiphers.remove(cipher);
		}
		else if(action.equals("server")){
			if(cb.isSelected())
				serverCiphers.add(cipher);
			else 
				serverCiphers.remove(cipher);
		}
		
	}

}
