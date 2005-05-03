/**
 * $Id: RadiusServer.java,v 1.3 2005/05/03 15:17:41 wuttke Exp $
 * Created on 09.04.2005
 * @author Matthias Wuttke
 * @version $Revision: 1.3 $
 */
package org.tinyradius.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.AccountingRequest;
import org.tinyradius.packet.RadiusPacket;

/**
 * Implements a simple Radius server. This class must be subclassed to
 * provide an implementation for getSharedSecret() and getUserPassword().
 * If the server supports accounting, it must override
 * accountingRequestReceived().
 */
public abstract class RadiusServer {
	
	/**
	 * Returns the shared secret used to communicate with the client with the
	 * passed IP address or null if the client is not allowed at this server.
	 * @param client IP address of client
	 * @return shared secret or null
	 */
	public abstract String getSharedSecret(InetAddress client);
	
	/**
	 * Returns the password of the passed user. Either this
	 * method or accessRequestReceived() should be overriden.
	 * @param userName user name
	 * @return plain-text password or null if user unknown
	 */
	public abstract String getUserPassword(String userName);
	
	/**
	 * Constructs an answer for an Access-Request packet. Either this
	 * method or isUserAuthenticated should be overriden.
	 * @param accessRequest Radius request packet
	 * @param client address of Radius client
	 * @return response packet or null if no packet shall be sent
	 * @exception RadiusException malformed request packet; if this
	 * exception is thrown, no answer will be sent
	 */
	public RadiusPacket accessRequestReceived(AccessRequest accessRequest, InetAddress client)
	throws RadiusException {
		String plaintext = getUserPassword(accessRequest.getUserName());
		int type = RadiusPacket.ACCESS_REJECT;
		if (plaintext != null && accessRequest.verifyPassword(plaintext))
			type = RadiusPacket.ACCESS_ACCEPT;
		return new RadiusPacket(type, accessRequest.getPacketIdentifier());
	}
	
	/**
	 * Constructs an answer for an Accounting-Request packet. This method
	 * should be overriden if accounting is supported.
	 * @param accountingRequest Radius request packet
	 * @param client address of Radius client
	 * @return response packet or null if no packet shall be sent
	 * @exception RadiusException malformed request packet; if this
	 * exception is thrown, no answer will be sent
	 */
	public RadiusPacket accountingRequestReceived(AccountingRequest accountingRequest, InetAddress client) 
	throws RadiusException {
		return new RadiusPacket(RadiusPacket.ACCOUNTING_RESPONSE, accountingRequest.getPacketIdentifier());
	}
	
	/**
	 * Starts the Radius server.
	 * @param listenAuth open auth port?
	 * @param listenAcct open acct port?
	 */
	public void start(boolean listenAuth, boolean listenAcct) {
		if (listenAuth) {
			new Thread() {
				public void run() {
					setName("Radius Auth Listener");
					try {
						logger.info("starting RadiusAuthListener on port " + getAuthPort());
						listenAuth();
					} catch(Exception e) {
						e.printStackTrace();
					}
				}
			}.start();
		}
		
		if (listenAcct) {
			new Thread() {
				public void run() {
					setName("Radius Acct Listener");
					try {
						logger.info("starting RadiusAcctListener on port " + getAcctPort());
						listenAcct();
					} catch(Exception e) {
						e.printStackTrace();
					}
				}
			}.start();
		}
	}
	
	/**
	 * Stops the server and closes the sockets.
	 */
	public void stop() {
		logger.info("stopping Radius server");
		if (authSocket != null)
			authSocket.close();
		if (acctSocket != null)
			acctSocket.close();
	}
	
	/**
	 * Returns the auth port the server will listen on.
	 * @return auth port
	 */
	public int getAuthPort() {
		return authPort;
	}
	
	/**
	 * Sets the auth port the server will listen on.
	 * @param authPort auth port, 1-65535
	 */
	public void setAuthPort(int authPort) {
		if (authPort < 1 || authPort > 65535)
			throw new IllegalArgumentException("bad port number");
		this.authPort = authPort;
		this.authSocket = null;
	}
	
	/**
	 * Returns the socket timeout (ms).
	 * @return socket timeout
	 */
	public int getSocketTimeout() {
		return socketTimeout;
	}
	
	/**
	 * Sets the socket timeout.
	 * @param socketTimeout socket timeout, >0 ms
	 * @throws SocketException
	 */
	public void setSocketTimeout(int socketTimeout)
	throws SocketException {
		if (socketTimeout < 1)
			throw new IllegalArgumentException("socket tiemout must be positive");
		this.socketTimeout = socketTimeout;
		if (authSocket != null)
			authSocket.setSoTimeout(socketTimeout);
		if (acctSocket != null)
			acctSocket.setSoTimeout(socketTimeout);
	}
	
	/**
	 * Sets the acct port the server will listen on.
	 * @param acctPort acct port 1-65535
	 */
	public void setAcctPort(int acctPort) {
		if (acctPort < 1 || acctPort > 65535)
			throw new IllegalArgumentException("bad port number");
		this.acctPort = acctPort;
		this.acctSocket = null;
	}

	/**
	 * Returns the acct port the server will listen on.
	 * @return acct port
	 */
	public int getAcctPort() {
		return acctPort;
	}
	
	/**
	 * Returns the duplicate interval in ms.
	 * A packet is discarded as a duplicate if in the duplicate interval
	 * there was another packet with the same identifier originating from the
	 * same address.
	 * @return duplicate interval
	 */
	public long getDuplicateInterval() {
		return duplicateInterval;
	}

	/**
	 * Sets the duplicate interval in ms.
	 * A packet is discarded as a duplicate if in the duplicate interval
	 * there was another packet with the same identifier originating from the
	 * same address.
	 * @param duplicateInterval duplicate interval, >0
	 */
	public void setDuplicateInterval(long duplicateInterval) {
		if (duplicateInterval <= 0)
			throw new IllegalArgumentException("duplicate interval must be positive");
		this.duplicateInterval = duplicateInterval;
	}
	
	/**
	 * Listens on the auth port (blocks the current thread).
	 * Returns when stop() is called.
	 * @throws SocketException
	 * @throws InterruptedException
	 */
	protected void listenAuth()
	throws SocketException {
		listen(getAuthSocket());
	}
		
	/**
	 * Listens on the acct port (blocks the current thread).
	 * Returns when stop() is called.
	 * @throws SocketException
	 * @throws InterruptedException
	 */
	protected void listenAcct()
	throws SocketException {
		listen(getAcctSocket());
	}

	/**
	 * Listens on the passed socket, blocks until stop() is called.
	 * @param s socket to listen on
	 */
	protected void listen(DatagramSocket s) {
		DatagramPacket packetIn = new DatagramPacket(new byte[RadiusPacket.MAX_PACKET_LENGTH], RadiusPacket.MAX_PACKET_LENGTH);
		while (true) {
			try {
				// receive packet
				try {
					s.receive(packetIn);
				} catch (SocketException se) {
					// end thread
					return;
				}
				
				// check client
				InetAddress address = packetIn.getAddress();				
				String secret = getSharedSecret(address);
				if (secret == null) {
					if (logger.isInfoEnabled())
						logger.info("ignoring packet from unknown client " + address);
					continue;
				}
				
				// parse packet
				RadiusPacket request = makeRadiusPacket(packetIn, secret);
				if (logger.isInfoEnabled())
					logger.info("received packet from " + address + ": " + request);
				
				// construct response
				RadiusPacket response = null;
				
				// check for duplicates
				if (!isPacketDuplicate(request, address)) {
					// handle request packet
					if (s == authSocket) {
						if (request instanceof AccessRequest)
							response = accessRequestReceived((AccessRequest)request, address);
						else
							logger.error("unknown Radius packet type: " + request.getPacketType());
					} else if (s == acctSocket) {
						if (request instanceof AccountingRequest)
							response = accountingRequestReceived((AccountingRequest)request, address);
						else
							logger.error("unknown Radius packet type: " + request.getPacketType());
					}
				} else
					logger.info("ignore duplicate packet");
				
				// send response
				if (response != null) {
					if (logger.isInfoEnabled())
						logger.info("send response: " + response);
					DatagramPacket packetOut = makeDatagramPacket(response, secret, address, packetIn.getPort(), request);
					s.send(packetOut);
				} else
					logger.info("no response sent");
			} catch (SocketTimeoutException ste) {
				// this is expected behaviour
			} catch (IOException ioe) {
				// error while reading/writing socket
				logger.error("communication error", ioe);
			} catch (RadiusException re) {
				// malformed packet
				logger.error("malformed Radius packet", re);
			}
		}
	}

	/**
	 * Returns a socket bound to the auth port.
	 * @return socket
	 * @throws SocketException
	 */
	protected DatagramSocket getAuthSocket() 
	throws SocketException {
		if (authSocket == null) {
			authSocket = new DatagramSocket(getAuthPort());
			authSocket.setSoTimeout(getSocketTimeout());
		}
		return authSocket;
	}

	/**
	 * Returns a socket bound to the acct port.
	 * @return socket
	 * @throws SocketException
	 */
	protected DatagramSocket getAcctSocket() 
	throws SocketException {
		if (acctSocket == null) {
			acctSocket = new DatagramSocket(getAcctPort());
			acctSocket.setSoTimeout(getSocketTimeout());
		}
		return acctSocket;
	}

	/**
	 * Creates a Radius response datagram packet from a RadiusPacket to be send. 
	 * @param packet RadiusPacket
	 * @param secret shared secret to encode packet
	 * @param address where to send the packet
	 * @param port destination port number
	 * @param request request packet
	 * @return new datagram packet
	 * @throws IOException
	 */
	protected DatagramPacket makeDatagramPacket(RadiusPacket packet, String secret, InetAddress address, int port,
			RadiusPacket request) 
	throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		packet.encodeResponsePacket(bos, secret, request);
		byte[] data = bos.toByteArray();
	
		DatagramPacket datagram = new DatagramPacket(data, data.length, address, port);
		return datagram;
	}
	
	/**
	 * Creates a RadiusPacket for a Radius request from a received
	 * datagram packet.
	 * @param packet received datagram
	 * @return RadiusPacket object
	 * @exception RadiusException malformed packet
	 * @exception IOException communication error (after getRetryCount()
	 * retries)
	 */
	protected RadiusPacket makeRadiusPacket(DatagramPacket packet, String sharedSecret) 
	throws IOException, RadiusException {
		ByteArrayInputStream in = new ByteArrayInputStream(packet.getData());
		return RadiusPacket.decodeRequestPacket(in, sharedSecret);
	}
	
	/**
	 * Checks whether the passed packet is a duplicate.
	 * A packet is duplicate if another packet with the same identifier
	 * has been sent from the same host in the last time. 
	 * @param packet packet in question
	 * @return true if it is duplicate
	 */
	protected boolean isPacketDuplicate(RadiusPacket packet, InetAddress address) {
		long now = System.currentTimeMillis();
		long intervalStart = now - getDuplicateInterval();
		
		for (Iterator i = receivedPackets.iterator(); i.hasNext();) {
			ReceivedPacket p = (ReceivedPacket)i.next();
			if (p.receiveTime < intervalStart) {
				// packet is older than duplicate interval
				i.remove();
			} else {
				if (p.address.equals(address) && p.packetIdentifier == packet.getPacketIdentifier()) {
					// packet is duplicate
					return true;
				}
			}
		}
		
		// add packet to receive list
		ReceivedPacket rp = new ReceivedPacket();
		rp.address = address;
		rp.packetIdentifier = packet.getPacketIdentifier();
		rp.receiveTime = now;
		receivedPackets.add(rp);
		return false;
	}
	
	private int authPort = 1812;
	private int acctPort = 1813;
	private DatagramSocket authSocket = null;
	private DatagramSocket acctSocket = null;
	private int socketTimeout = 3000;
	private List receivedPackets = new LinkedList();
	private long duplicateInterval = 30000; // 30 s
	private static Log logger = LogFactory.getLog(RadiusServer.class);
	
}

/**
 * This internal class represents a packet that has been received by 
 * the server.
 */
class ReceivedPacket {
	
	/**
	 * The identifier of the packet.
	 */
	public int packetIdentifier;
	
	/**
	 * The time the packet was received.
	 */
	public long receiveTime;
	
	/**
	 * The address of the host who sent the packet.
	 */
	public InetAddress address;
	
}
