
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
* Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
*   - Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*   - Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in the
*     documentation and/or other materials provided with the distribution.
*
*   - Neither the name of Sun Microsystems nor the names of its
*     contributors may be used to endorse or promote products derived
*     from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
* PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * Klasse, um die Zertifikate eines Server zu den vertrauten (trusted), eigenen Java-Zertifikaten des JDK
 * anzuh&auml;ngen. 
 * 
 * <br /><br />
 * 
 * Originally from: <br />
 * http://blogs.sun.com/andreas/resource/InstallCert.java <br />
 * Use: <br />
 * java InstallCert hostname <br />
 * Example (Konsoleneingabe): <br />
 * java InstallCert ecc.fedora.redhat.com <br />
 *
 * <br /><br />
 * 
 * <b>wichtige Zusatzinformation</b> <br /><br />
 * 
 * Die Original Klasse verbindet sich auf beliebige Public-Server &uuml;ber Standard-Ports um Zertifikate zu erhalten.<br /><br />
 * 
 * {@link de.medys.ldap.MedysLdapConnection} ben&ouml;tigt jedoch die Angabe einer SSL-Server-Portangabe. <br /><br />
 * 
 * Daher der Aufruf per Konsole <br /><br />
 * 
 * java InstallCert ecc.fedora.redhat.com &lt;SSL-SERVER PORT-ANGABE&gt;
 * 
 * <br / ><br />
 * 
 */
public class InstallCert {

	private boolean sslSocketConnEstablished;
	
	private boolean handshakeDone, serverCertificateReceived;
	
	private char[] passphrase;
	
	private KeyStore keystore;
	
	private SavingTrustManager savingTrustManager;
	
	private SSLSocket sslSocket;
	
	public InstallCert()
	{
		sslSocketConnEstablished = false;
		
		serverCertificateReceived = false;
		
		handshakeDone = false;
	}
	
	/**
	 * Erstellt eine neue Instanz von InstallCert.
	 * 
	 * <br/><br/>
	 * 
	 * Erh&auml;lt den Schlüsselverbund (default KeyStore) und stellt
	 * eine SSL-Verbindung zu einem Server her.
	 * 
	 * <br/><br/>  
	 * 
	 * @param hostName der Server-Name, wie <i>serverlogic.ademus.com</i> <br/>
	 * 				   <b>OHNE</b> Pefix-Angabe wie <i>http://</i> oder <i>ldap://</i>
	 * 
	 * @param port die Port-Nummer des Servers
	 */
    public InstallCert(String hostName, String port) {
    
    	sslSocketConnEstablished = false;
		
    	serverCertificateReceived = false;
		
    	doConnect(hostName, port);
    }
    
    /**
     * Stellt eine Verbindung zu einem Host-Rechner an einem gegebenen Rechner-Port her.
     * 
     * <br /><br />
     * 
     * <b>wichtige Info</b><br /><br />
     * 
     * Diese Methode kann <u>nur in Verbindung</u> mit einer <b>SSL-Socket Verbindung</b> genutzt werden.<br />
     * 
     * <br />
     * 
     * @param hostName der Hostrechner-Name
     * @param port der Port des Hostrechners
     */
    public void doConnect(String hostName, String port)
    {	
    	// erhalte den KeyStore (TrustStore vom Java-Zertifikatstapel)
    	keystore = getKeyStore();
    	
    	// Zertifikat in KeyStore gespeichert
    	//
    	openSSLSocketWithKeystore(hostName, port);
    	
    	if(sslSocketConnEstablished)
    	{
    		System.out.println("Connection established..");
    		handshake(hostName, port);
    	}
    	else
    	{
    		System.out.println("Could not connect to Socket " + port + " on " + hostName);
    	}
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {
            throw new UnsupportedOperationException();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }
    
    /**
     * Gibt den aktuellen Schlüsselverbudng des isntallierten JDKs
     * auf der aktuellen Rechnermaschine zur&uuml;ck
     * 
     * <p></p>
     * 
     * @return cacerts.keystore-Datei aus dem installeirten JDK des Benutzers
     */
    public KeyStore getKeyStore()
    {
    	// es wird kein Passwort für den KEyStore mitgeliefert
    	//
    	// daher wird nach SUN-Vorlage , daß Passwort für den temporären Zugang
    	// zum KeyStore durch "changeit"-Kommando ausgeschaltet
    	//
    	return getKeyStore("changeit".toCharArray());
    }
    
    /**
     * Status, ob der Server "handshake" (dem Zertifikat gekolppelt mit dieser Anwendung) 
     * zugetimmt hat oder nicht
     * 
     * @return TRUE wenn Zertifikat gültig und handshake erfolgt ist, sonst FALSE
     */
    public boolean getServerHandshakeAccomplished()
    {
    	return handshakeDone;
    }
    
    /*
     * SSL-Connection Handshake Prozedur mit "Server hostName"
     */
    private void handshake(String hostName, String port)
    {
    	try
    	{
			try {
				
				System.out.println("Starting SSL handshake...");
				
				sslSocket.startHandshake();
				sslSocket.close();

				handshakeDone = true;
				
				System.out.println();
				System.out.println("No errors, certificate is already trusted");

			}
			catch (SSLException noHandshake) {
				
				System.out.println("Error, certificate not trusted yet, " 
			     + "trying to Reconnect after storing X509-Certificate.");
				
				// 
				X509Certificate[] chain = savingTrustManager.chain;

				if (chain == null) {
					System.out.println("Could not obtain server certificate chain");
					return;
				}

				System.out.println();
				System.out.println("Server sent " + chain.length
						+ " certificate(s):");
				System.out.println();

				int k = 0;

				X509Certificate cert = chain[k];
				String alias = hostName + "-" + (k + 1);
				keystore.setCertificateEntry(alias, cert);

				// JSSECacerts-Datei existiert hier bereits !!
				//
				OutputStream out = new FileOutputStream("jssecacerts");

				passphrase = "changeit".toCharArray();

				keystore.store(out, passphrase);

				System.out.println();
				System.out.println(cert);
				System.out.println();
				System.out
						.println("Added certificate to keystore 'jssecacerts' using alias '"
								+ alias + "'");
				
				handshakeDone = true;
				
				out.close();

				sslSocket.close();
			}
		} 
    	catch (IOException ioExcep) {
			System.out.println("IOException in doHandshake(): "
					+ ioExcep.getMessage());
			ioExcep.printStackTrace();
		} 
    	catch (KeyStoreException kse) {
			System.out.println("KeyStoreException in doHandshake(): "
					+ kse.getMessage());
			kse.printStackTrace();
		}
    	catch (CertificateException certExcep) {
			System.out.println("CertificateException in doHandshake(): "
					+ certExcep.getMessage());
			certExcep.printStackTrace();
		}
    	catch (NoSuchAlgorithmException noAlgol) {
			System.out.println("NoSuchAlgorithmException in doHandshake(): "
					+ noAlgol.getMessage());
			noAlgol.printStackTrace();
		}
    }
    
    /*
     *
     * Gibt den Java- Schlüsselverbund (Keystore) ,wo sich der Zertifikatstapel befindet, zurück
     * 
     * Info:
     * -----
     * 
     * Der Parameter "passphrase" stellt das Passwort des JDK-KeyStore dar.
     * 
     * Da in der Regel dieser Zertifikatsstapel (KeyStore) des JDK nicht mit einem Passwort
     * belegt wird, ist der Wert des Parameters ständig "changeit", welches sich an die
     * SUN Microsystems/Oracle Vorlage hält.
     * 
     * siehe auch: https://docs.oracle.com/cd/E19957-01/817-3331/6miuccqo2/index.html
     * 
     * @param passphrase Password des KeyStore (auch default Pfad des KeyStore)
     */ 
    private KeyStore getKeyStore(char[] passphrase)
    {	
    	
    	// Schlüsselverbund
    	
    	KeyStore ks = null;
    	
    	// bestimme die Datei, welceh den KeyStore repräsentiert
    	// und das Server-zertifikat enthalten soll
    	//
        File jsseCacerts = new File("jssecacerts");
        
        // die Datei kann bereits aus einer vorherigen Benutzung
        // dieser Anwendung existieren, lösche Sie dann
        // um nur das neue Server-Zertifikat zu speichern
        //
        if(jsseCacerts.exists())
        {
        	if (jsseCacerts.delete()) 
        	{
        		// definiere leere Datei
        		//
        		jsseCacerts = new File("jssecacerts");
        	}
        	else
        	{
        		System.out.println("Kann " + jsseCacerts + "-Datei nicht löschen !!");
        	}
        }
		try {
			// erstellt die Datei (vorher nur definiert oder bereits vorhanden und dann gelöscht)
			//
			FileWriter fw = new FileWriter(jsseCacerts);
			fw.close();
		}
		catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        

		System.out.println("Loading KeyStore " + jsseCacerts + "...");

		// speichere Server-Zertifikat in den temporären TrustStore
		// "jssecacerts"
		//
		try 
		{
			
			// Default-Keystore laden ohne Angabe einer Datei
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null, passphrase);
				
			// in Keystore-Datei schreiben 
			FileOutputStream writer = new FileOutputStream(jsseCacerts);
			ks.store(writer, passphrase);
			writer.close();
			
			// diese dann laden
			FileInputStream in = new FileInputStream(jsseCacerts);
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(in, passphrase);
			in.close();
			
			// gib an, welches TrustStore diese Anwendung vertraut
			//
			// siehe hierzu
			//
			// http://stackoverflow.com/questions/5871279/java-ssl-and-cert-keystore
			//
			System.setProperty("javax.net.ssl.trustStore",
					jsseCacerts.getAbsolutePath());

			System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

			serverCertificateReceived = true;
		}
		catch (KeyStoreException keyStoreExcep) 
		{
			keyStoreExcep.printStackTrace();
		} 
		catch (NoSuchAlgorithmException md5Excep) 
		{
			System.out.println("MD5 Digest Error");
			md5Excep.printStackTrace();
		} 
		catch (CertificateException certicateExcep) 
		{
			System.out.println("X.509 Zertifikat Error");
			certicateExcep.printStackTrace();
		} 
		catch (IOException readIO) 
		{
			System.out.println("readLine Error or File not found");
			readIO.printStackTrace();
		}
        return ks;
    }
    
    /*
     * &Ouml;ffnet eine "Secure-Socket-Connection"
     * 
     * <br>/<br/>
     * 
     * Der HostName des Servers muss ohne URL-PREFIX Angaben angegeben werden. <br/><br/>
     * 
     * Valdie HostNamen w&auml;ren <br/><br/>
     * 
     * <i>kvc-1.kvtg.kbv.de</i> statt 
     * @param hostName der Hostname des Servers (ohne URL-Prefix wie http: ldap: oder ftp:)
     * @param port
     * @param keystore
     */
    private void openSSLSocketWithKeystore(String hostName, String port) 
    {  	
    	try
    	{	
    		handshakeDone = false;
    		
    		if(serverCertificateReceived)
    		{
				SSLContext context = SSLContext.getInstance("TLS");

				TrustManagerFactory tmf = TrustManagerFactory
						.getInstance(TrustManagerFactory.getDefaultAlgorithm());

				tmf.init(keystore);

				X509TrustManager defaultTrustManager = (X509TrustManager) tmf
						.getTrustManagers()[0];

				savingTrustManager = new SavingTrustManager(defaultTrustManager);

				context.init(null, new TrustManager[] { savingTrustManager },
						null);

				SSLSocketFactory factory = context.getSocketFactory();

				System.out.println("Opening connection to " + hostName + ":"
						+ port + "...");
				sslSocket = (SSLSocket) factory.createSocket(hostName,
						new Integer(port));

				sslSocket.setSoTimeout(10000);

				sslSocketConnEstablished = true;
    		}
    		else
    		{
    			sslSocketConnEstablished = false;
    		}
    	}
		catch (SSLException e)
		{
			System.out.println();
			e.printStackTrace(System.out);
			
			sslSocketConnEstablished = false;
		}
    	catch(KeyStoreException kse)
    	{
    		System.out.println("KeyStoreExeception in  InstallCert.openSSLSocket(..):\n\n" 
    					+ kse.getMessage());
    		kse.printStackTrace();
    		
    		sslSocketConnEstablished = false;
    	}
    	catch(KeyManagementException ksme)
    	{
    		System.out.println("KeyStoreManagementException in openSLLSocket():\n\n"
    				+  ksme.getMessage());
    		ksme.printStackTrace();
    		
    		sslSocketConnEstablished = false;
    	}
    	catch(NoSuchAlgorithmException noalgol) 
    	{
    		System.out.println("NoSuchAlgorithmException in openSSLSocket():\n\n"
    				+ noalgol.getMessage());
    		noalgol.printStackTrace();
    		
    		sslSocketConnEstablished = false;
    	}
    	catch(SocketException se)
    	{
    		System.out.println("SocketException: " + se.getMessage());
    		se.printStackTrace();
    		
    		sslSocketConnEstablished = false;
    	}
    	catch(UnknownHostException uhe)
    	
    	{
    		System.out.println("Unbekannter Hsot-Name:\nn›"
    				 + uhe.getMessage());
    		uhe.printStackTrace();
    		
    		sslSocketConnEstablished = false;
    	}
    	catch(IOException ioe)
    	{
    		System.out.println("IOException aus openSSLSocket():\n\n"
    				+ ioe.getMessage());
    		ioe.printStackTrace();
    		
    		sslSocketConnEstablished = false;
    	}
    }
}
