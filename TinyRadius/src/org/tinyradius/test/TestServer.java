/**
 * $Id: TestServer.java,v 1.2 2005/05/03 15:17:43 wuttke Exp $
 * Created on 08.04.2005
 * @author Matthias Wuttke
 * @version $Revision: 1.2 $
 */
package org.tinyradius.test;

import java.io.IOException;
import java.net.InetAddress;

import org.tinyradius.attribute.StringAttribute;
import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.util.RadiusException;
import org.tinyradius.util.RadiusServer;

/**
 * Test server which terminates after 30 s.
 * Knows only the client "localhost" with secret "testing123" and
 * the user "mw" with the password "test".
 */
public class TestServer {
	
	public static void main(String[] args) 
	throws IOException, Exception {
		RadiusServer server = new RadiusServer() {
			// Authorize localhost/testing123
			public String getSharedSecret(InetAddress client) {
				if (client.getHostAddress().equals("127.0.0.1"))
					return "testing123";
				else
					return null;
			}
			
			// Authenticate mw
			public String getUserPassword(String userName) {
				if (userName.equals("mw"))
					return "test";
				else
					return null;
			}
			
			// Adds an attribute to the Access-Accept packet
			public RadiusPacket accessRequestReceived(AccessRequest accessRequest, InetAddress client) 
			throws RadiusException {
				System.out.println("Received Access-Request:\n" + accessRequest);
				RadiusPacket packet = super.accessRequestReceived(accessRequest, client);
				if (packet.getPacketType() == RadiusPacket.ACCESS_ACCEPT)
					packet.addAttribute(new StringAttribute(18, "Welcome " + accessRequest.getUserName() + "!"));
			
				if (packet == null)
					System.out.println("Ignore packet.");
				else
					System.out.println("Answer:\n" + packet);
				return packet;
			}
		};
		
		server.start(true, true);
		
		System.out.println("Server started.");
		
		Thread.sleep(1000*30);
		System.out.println("Stop server (30 s expired)");
		server.stop();
	}
	
}
