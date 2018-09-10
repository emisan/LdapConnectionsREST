import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

import javax.net.ssl.HttpsURLConnection;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import de.medys.MedysFileIO;
import de.medys.datacompress.GZip;
import de.medys.datacompress.Zip;
import de.medys.datadecompress.Unzip;


public class TestServices {

	public static void main(String[] args) {
		URL url;
		try {
			url = new URL("https://kvc-2.kvtg.kbv.de:8443/kvconnect/rest/");
			try {
				InstallCert certInst = new InstallCert(url.getHost(), String.valueOf(url.getPort()));
				
				HttpsURLConnection connection =  (HttpsURLConnection)url.openConnection();
				
				if(connection != null)
				{
					if(certInst.getServerHandshakeAccomplished())
					{
						connection.connect();
						
						Client client = ClientBuilder.newClient();
						
						System.out.println("kvc-2.kvtg.kbv.de-Server Version: " 
						+ requestServerVersion(true, client, connection.getURL(), "server/version"));
						
//						System.out.println("UID von Marc Steffen @ Medys: " + doLoginAndGetUID(true, client, url, "marc", "steffen", "medys.1"));
						
						boolean accountsGeladen = ladeAlleAccounts(true, client, connection.getURL());
						
					}
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static Builder getRequestBuilder(Client forClient, URL clientConnectionURL, String requestedRESTpath)
	throws IOException
	{
		Builder builder = null;
		
		if((clientConnectionURL != null) && (forClient != null) && (requestedRESTpath != null))
		{
			WebTarget webTarget = forClient.target(clientConnectionURL.toExternalForm());
			
			if(webTarget != null)
			{

				builder = webTarget.path(requestedRESTpath).request();
			}
		}
		return builder;
	}
	
	public static Builder getRequestBuilderWithMediaType(Client forClient, URL clientConnectionURL, String requestedRESTpath, MediaType mediaType)
	throws IOException
	{
		Builder builder = null;
		
		if((clientConnectionURL != null) && (forClient != null) && (requestedRESTpath != null))
		{
			WebTarget webTarget = forClient.target(clientConnectionURL.toExternalForm());
			
			if(webTarget != null)
			{
				if(mediaType != null)
				{
					builder = webTarget.path(requestedRESTpath).request(mediaType);
				}
			}
		}
		return builder;
	}
	
	public static boolean ladeAlleAccounts(boolean connected, Client client, URL clientConnectionURL) throws IOException
	{
		boolean status = false;
		
		if(connected)
		{
			Builder builder = getRequestBuilder(client, clientConnectionURL, "/vzd/accounts.xml.zip");
			
			if(builder != null)
			{
				File zipFile = builder.get(File.class);
				
				try {
					new Unzip().unzip(zipFile, System.getProperty("user.home") + File.separator + "Desktop", zipFile.getName());
					
					status = true;
					
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		return status;
	}
	
	
	public static String requestServerVersion(boolean connected, Client client, URL clientConnectionURL, String restServerVersionPath) throws IOException
	{
		String version = null;
		
		if(connected)
		{
			Builder builder = getRequestBuilder(client, clientConnectionURL, restServerVersionPath);
			
			if(builder != null)
			{
				version = builder.get(String.class);
			}
		}
		
		return version;
	}
	
	public static String doLoginAndGetUID(boolean connected, Client fromClient, URL clientConnectionURL, String userSurname, String userName, String organisation)
	{
		String uid = null;
		
		if((clientConnectionURL != null) && connected && (fromClient != null))
		{
			WebTarget webTarget = fromClient.target(clientConnectionURL.toExternalForm());
			
			if(webTarget != null)
			{
				Builder builder = webTarget.path("accounts/").path(userSurname).path(userName).path(organisation).request(MediaType.APPLICATION_XML_TYPE);
				
				if(builder != null)
				{
					System.out.println(builder.get(String.class));
					uid = builder.get(String.class);
				}
			}
		}
		return uid;
	}
}
