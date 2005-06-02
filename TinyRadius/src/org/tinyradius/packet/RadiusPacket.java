/**
 * $Id: RadiusPacket.java,v 1.2 2005/06/02 14:22:08 wuttke Exp $
 * Created on 07.04.2005
 * Released under the LGPL
 * @author Matthias Wuttke
 * @version $Revision: 1.2 $
 */
package org.tinyradius.packet;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.tinyradius.attribute.AttributeType;
import org.tinyradius.attribute.AttributeTypes;
import org.tinyradius.attribute.RadiusAttribute;
import org.tinyradius.attribute.VendorSpecificAttribute;
import org.tinyradius.util.RadiusException;
import org.tinyradius.util.RadiusUtil;

/**
 * This class represents a Radius packet. Subclasses provide convenience methods
 * for special packet types.
 */
public class RadiusPacket {
	
    /**
     * Packet type codes.
     */
	public static final int ACCESS_REQUEST      = 1;
	public static final int ACCESS_ACCEPT       = 2;
	public static final int ACCESS_REJECT       = 3;
	public static final int ACCOUNTING_REQUEST  = 4;
	public static final int ACCOUNTING_RESPONSE = 5;
	public static final int ACCOUNTING_STATUS   = 6;
	public static final int PASSWORD_REQUEST    = 7;
	public static final int PASSWORD_ACCEPT     = 8;
	public static final int PASSWORD_REJECT     = 9;
	public static final int ACCOUNTING_MESSAGE  = 10;
	public static final int ACCESS_CHALLENGE    = 11;
	public static final int STATUS_SERVER       = 12;   // experimental
	public static final int STATUS_CLIENT       = 13;   // experimental
	public static final int RESERVED            = 255;

	/**
	 * Maximum packet length.
	 */
	public static final int MAX_PACKET_LENGTH = 4096;
	
	/**
	 * Packet header length.
	 */
    public static final int RADIUS_HEADER_LENGTH  = 20;

	/**
	 * Builds a Radius packet without attributes. Retrieves
	 * the next packet identifier.
	 * @param type packet type 
	 */
	public RadiusPacket(final int type) {
	    this(type, getNextPacketIdentifier(), new ArrayList());
	}
	
	/**
	 * Builds a Radius packet with the given type and identifier
	 * and without attributes.
	 * @param type packet type
	 * @param identifier packet identifier
	 */
	public RadiusPacket(final int type, final int identifier) {
	    this(type, identifier, new ArrayList());
	}
	
	/**
	 * Builds a Radius packet with the given type, identifier and
	 * attributes. 
	 * @param type packet type
	 * @param identifier packet identifier
	 * @param attributes list of RadiusAttribute objects
	 */
	public RadiusPacket(final int type, final int identifier, final List attributes) {
		setPacketType(type);
	    setPacketIdentifier(identifier);
	    setAttributes(attributes);
	}
	
	/**
	 * Builds an empty Radius packet.
	 */
	public RadiusPacket() {
	}
	
	/**
	 * Returns the packet identifier for this Radius packet.
	 * @return packet identifier
	 */
	public int getPacketIdentifier() {
		return packetIdentifier;
	}
	
	/**
	 * Sets the packet identifier for this Radius packet.
	 * @param identifier packet identifier, 0-255
	 */
	public void setPacketIdentifier(int identifier) {
		if (identifier < 0 || identifier > 255)
			throw new IllegalArgumentException("packet identifier out of bounds");
		this.packetIdentifier = identifier;
	}
	
	/**
	 * Returns the type of this Radius packet.
	 * @return packet type
	 */
	public int getPacketType() {
		return packetType;
	}
	
	/**
	 * Returns the type name of this Radius packet.
	 * @return name
	 */
	public String getPacketTypeName() {
		switch (getPacketType()) {
		case ACCESS_REQUEST: return "Access-Request";
		case ACCESS_ACCEPT: return "Access-Accept";
		case ACCESS_REJECT: return "Access-Reject";
		case ACCOUNTING_REQUEST : return "Accounting-Request";
		case ACCOUNTING_RESPONSE: return "Accounting-Response";
		case ACCOUNTING_STATUS: return "Accounting-Status";
		case PASSWORD_REQUEST: return "Password-Request";
		case PASSWORD_ACCEPT: return "Password-Accept";
		case PASSWORD_REJECT: return "Password-Reject";
		case ACCOUNTING_MESSAGE: return "Accounting-Message";
		case ACCESS_CHALLENGE: return "Access-Challenge";
		case STATUS_SERVER: return "Status-Server";
		case STATUS_CLIENT: return "Status-Client";
		case RESERVED: return "Reserved";
		default: return "Unknown (" + getPacketType() + ")";
		}
	}
	
	/**
	 * Sets the type of this Radius packet.
	 * @param type packet type, 0-255
	 */
	public void setPacketType(int type) {
		if (type < 1 || type > 255)
			throw new IllegalArgumentException("packet type out of bounds");
		this.packetType = type;
	}
	
	/**
	 * Sets the list of attributes for this Radius packet.
	 * @param attributes list of RadiusAttribute objects
	 */
	public void setAttributes(List attributes) {
		if (attributes == null)
			throw new NullPointerException("attributes list is null");
		
		for (Iterator i = attributes.iterator(); i.hasNext();) {
			Object element = i.next();
			if (!(element instanceof RadiusAttribute))
				throw new IllegalArgumentException("attribute not an instance of RadiusAttribute");
		}
		
		this.attributes = attributes;
	}
	
	/**
	 * Adds a Radius attribute to this packet.
	 * @param attribute RadiusAttribute object
	 */
	public void addAttribute(RadiusAttribute attribute) {
		if (attribute == null)
			throw new NullPointerException("attribute is null");
		this.attributes.add(attribute);
	}
	
	/**
	 * Adds a Radius attribute to this packet.
	 * Uses AttributeTypes to lookup the type code and converts
	 * the value.
	 * @param typeName name of the attribute, for example "NAS-Ip-Address"
	 * @param value value of the attribute, for example "127.0.0.1"
	 * @throws IllegalArgumentException if type name is unknown
	 */
	public void addAttribute(String typeName, String value) {
		if (typeName == null || typeName.length() == 0)
			throw new IllegalArgumentException("type name is empty");
		if (value == null || value.length() == 0)
			throw new IllegalArgumentException("value is empty");
		
		AttributeType type = AttributeTypes.getAttributeType(typeName);
		if (type == null)
			throw new IllegalArgumentException("unknown attribute type '" + typeName + "'");
		
		RadiusAttribute attribute = RadiusAttribute.createRadiusAttribute(type.getTypeCode());
		attribute.setAttributeValue(value);
		addAttribute(attribute);
	}
	
	/**
	 * Removes the specified attribute from this packet.
	 * @param attribute RadiusAttribute to remove
	 */
	public void removeAttribute(RadiusAttribute attribute) {
		if (!this.attributes.remove(attribute))
			throw new IllegalArgumentException("no such attribute");
	}
	
	/**
	 * Removes all attributes from this packet which have got
	 * the specified type.
	 * @param type attribute type to remove
	 */
	public void removeAttributes(int type) {
		if (type < 1 || type > 255)
			throw new IllegalArgumentException("attribute type out of bounds");
		
		Iterator i = attributes.iterator();
		while (i.hasNext()) {
			RadiusAttribute attribute = (RadiusAttribute)i.next();
			if (attribute.getAttributeType() == type)
				i.remove();
		}
	}
	
	/**
	 * Returns all attributes of this packet of the given type.
	 * Returns an empty list if there are no such attributes.
	 * @param attributeType type of attributes to get 
	 * @return list of RadiusAttribute objects, does not return null
	 */
	public List getAttributes(int attributeType) {
		if (attributeType < 1 || attributeType > 255)
			throw new IllegalArgumentException("attribute type out of bounds");

		LinkedList result = new LinkedList();
		for (Iterator i = attributes.iterator(); i.hasNext();) {
			RadiusAttribute a = (RadiusAttribute)i.next();
			if (attributeType == a.getAttributeType())
				result.add(a);
		}
		return result;
	}
	
	/**
	 * Returns a list of all attributes belonging to this Radius
	 * packet.
	 * @return List of RadiusAttribute objects
	 */
	public List getAttributes() {
		return attributes;
	}
	
	/**
	 * Returns a Radius attribute of the given type which may only occur once
	 * in the Radius packet.
	 * @param type attribute type
	 * @return RadiusAttribute object or null if there is no such attribute
	 * @throws RuntimeException if there are multiple occurences of the
	 * requested attribute type
	 */
	public RadiusAttribute getAttribute(int type) {
		List attrs = getAttributes(type);
		if (attrs.size() > 1)
			throw new RuntimeException("multiple attributes of requested type " + type);
		else if (attrs.size() == 0)
			return null;
		else
			return (RadiusAttribute)attrs.get(0);
	}

	/**
	 * Returns a single Radius attribute of the given type name.
	 * @param type attribute type name
	 * @return RadiusAttribute object or null if there is no such attribute
	 * @throws RuntimeException if the attribute occurs multiple times
	 */
	public RadiusAttribute getAttribute(String type) {
		if (type == null || type.length() == 0)
			throw new IllegalArgumentException("type name is empty");
		
		AttributeType t = AttributeTypes.getAttributeType(type);
		if (t == null)
			throw new IllegalArgumentException("unknown attribute type name '" + type + "'");
		
		RadiusAttribute attr = getAttribute(t.getTypeCode());
		if (attr == null)
			return null;
		else
			return attr;
	}

	/**
	 * Returns the value of the Radius attribute of the given type or
	 * null if there is no such attribute.
	 * @param type attribute type name
	 * @return value of the attribute as a string or null if there
	 * is no such attribute
	 * @throws IllegalArgumentException if the type name is unknown
	 * @throws RuntimeException attribute occurs multiple times
	 */
	public String getAttributeValue(String type) {
		if (type == null || type.length() == 0)
			throw new IllegalArgumentException("type name is empty");
		
		AttributeType t = AttributeTypes.getAttributeType(type);
		if (t == null)
			throw new IllegalArgumentException("unknown attribute type name '" + type + "'");
		
		RadiusAttribute attr = getAttribute(t.getTypeCode());
		if (attr == null)
			return null;
		else
			return attr.getAttributeValue();
	}
	
	/**
	 * Returns the Vendor-Specific attribute for the given vendor ID.
	 * If there is more than one Vendor-Specific
	 * attribute with the given vendor ID, the first attribute found is
	 * returned. If there is no such attribute, null is returned.
	 * @param vendorId vendor ID of the attribute
	 * @return the attribute or null if there is no such attribute
	 */
	public VendorSpecificAttribute getVendorAttribute(int vendorId) {
		for (Iterator i = getAttributes(VendorSpecificAttribute.VENDOR_SPECIFIC).iterator(); i.hasNext();) {
			VendorSpecificAttribute vsa = (VendorSpecificAttribute)i.next();
			if (vsa.getVendorId() == vendorId)
				return vsa;
		}
		return null;
	}

	/**
	 * Encodes this Radius packet and sends it to the specified output
	 * stream.
	 * @param out output stream to use
	 * @param sharedSecret shared secret to be used to encode this packet
	 * @exception IOException communication error
	 */
	public void encodeRequestPacket(OutputStream out, String sharedSecret) 
	throws IOException {
		encodePacket(out, sharedSecret, null);
	}
	
	/**
	 * Encodes this Radius response packet and sends it to the specified output
	 * stream.
	 * @param out output stream to use
	 * @param sharedSecret shared secret to be used to encode this packet
	 * @param request Radius request packet
	 * @exception IOException communication error
	 */
	public void encodeResponsePacket(OutputStream out, String sharedSecret, RadiusPacket request) 
	throws IOException {
		if (request == null)
			throw new NullPointerException("request cannot be null");
		encodePacket(out, sharedSecret, request);
	}
	
	/**
	 * Reads a Radius request packet from the given input stream and
	 * creates an appropiate RadiusPacket descendant object.
	 * Reads in all attributes and returns the object. 
 	 * Decodes the encrypted fields and attributes of the packet.
	 * @param sharedSecret shared secret to be used to decode this packet
	 * @return new RadiusPacket object
	 * @exception IOException IO error
	 * @exception RadiusException malformed packet
	 */
	public static RadiusPacket decodeRequestPacket(InputStream in, String sharedSecret) 
	throws IOException, RadiusException {
		return decodePacket(in, sharedSecret, null);
	}
	
	/**
	 * Reads a Radius response packet from the given input stream and
	 * creates an appropiate RadiusPacket descendant object.
	 * Reads in all attributes and returns the object.
	 * Checks the packet authenticator. 
	 * @param sharedSecret shared secret to be used to decode this packet
	 * @param request Radius request packet
	 * @return new RadiusPacket object
	 * @exception IOException IO error
	 * @exception RadiusException malformed packet
	 */
	public static RadiusPacket decodeResponsePacket(InputStream in, String sharedSecret, RadiusPacket request) 
	throws IOException, RadiusException {
		if (request == null)
			throw new NullPointerException("request may not be null");
		return decodePacket(in, sharedSecret, request);
	}
	
	
	/**
	 * Retrieves the next packet identifier to use and increments the static
	 * storage.
	 * @return the next packet identifier to use
	 */
	public static synchronized int getNextPacketIdentifier(){
		nextPacketId++;
		if (nextPacketId > 255)
			nextPacketId = 0;
		return nextPacketId;
	}
	
	/**
	 * Creates a RadiusPacket object. Depending on the passed type, the
	 * appropiate successor is chosen. Sets the type, but does not touch
	 * the packet identifier.
	 * @param type packet type
	 * @return RadiusPacket object
	 */
	public static RadiusPacket createRadiusPacket(final int type) {
		RadiusPacket rp;
		switch (type) {
		case ACCESS_REQUEST:
			rp = new AccessRequest();
			break;
		
		case ACCOUNTING_REQUEST:
			rp = new AccountingRequest();
			break;
		
		case ACCESS_ACCEPT:
		case ACCESS_REJECT:
		case ACCOUNTING_RESPONSE:
		default:
			rp = new RadiusPacket();
		}
		
		rp.setPacketType(type);
		return rp;
	}
	
	/**
	 * String representation of this packet, for debugging purposes.
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		StringBuffer s = new StringBuffer();
		s.append(getPacketTypeName());
		s.append(", ID ");
		s.append(packetIdentifier);
		for (Iterator i = attributes.iterator(); i.hasNext();) {
			RadiusAttribute attr = (RadiusAttribute)i.next();
			s.append("\n");
			s.append(attr.toString());
		}
		return s.toString();
	}
	
	/**
	 * Returns the authenticator for this Radius packet.
	 * For a Radius packet read from a stream, this will return the
	 * authenticator sent by the server. For a new Radius packet to be sent,
	 * this will return the authenticator created by the method
	 * createAuthenticator() and will return null if no authenticator
	 * has been created yet.
	 * @return authenticator, 16 bytes
	 */
	public byte[] getAuthenticator() {		
		return authenticator;
	}

	/**
	 * Encodes this Radius packet and sends it to the specified output
	 * stream.
	 * @param out output stream to use
	 * @param sharedSecret shared secret to be used to encode this packet
	 * @param request Radius request packet if this packet to be encoded
	 * is a response packet, null if this packet is a request packet
	 * @exception IOException communication error
	 * @exception RuntimeException if required packet data has not been set 
	 */
	protected void encodePacket(OutputStream out, String sharedSecret, RadiusPacket request) 
	throws IOException {
		// check shared secret
		if (sharedSecret == null || sharedSecret.length() == 0)
			throw new RuntimeException("no shared secret has been set");
		
		// check request authenticator
		if (request != null && request.getAuthenticator() == null)
			throw new RuntimeException("request authenticator not set");

		// request packet authenticator
		if (request == null) {
			// first create authenticator, then encode attributes
			// (User-Password attribute needs the authenticator)
			authenticator = createRequestAuthenticator(sharedSecret);
			encodeRequestAttributes(sharedSecret);
		}

		byte[] attributes = getAttributeBytes();
		int packetLength = RADIUS_HEADER_LENGTH + attributes.length;
		if (packetLength > MAX_PACKET_LENGTH)
			throw new RuntimeException("packet too long");
		
		// response packet authenticator
		if (request != null) {
			// after encoding attributes, create authenticator
			authenticator = createResponseAuthenticator(sharedSecret, packetLength, attributes, request.getAuthenticator());
		} else {
			// update authenticator after encoding attributes
			authenticator = updateRequestAuthenticator(sharedSecret, packetLength, attributes);
		}
	
		DataOutputStream dos = new DataOutputStream(out);
		dos.writeByte(getPacketType());
		dos.writeByte(getPacketIdentifier());
		dos.writeShort(packetLength);
		dos.write(getAuthenticator());
		dos.write(attributes);
		dos.flush();
	}

	/**
	 * This method exists for subclasses to be overridden in order to
	 * encode packet attributes like the User-Password attribute.
	 * The method may use getAuthenticator() to get the request
	 * authenticator.
	 * @param sharedSecret
	 */
	protected void encodeRequestAttributes(String sharedSecret) {
	}
	
	/**
	 * Creates a request authenticator for this packet. This request authenticator
	 * is constructed as described in RFC 2865.
	 * @param sharedSecret shared secret that secures the communication
	 * with the other Radius server/client
	 * @return request authenticator, 16 bytes
	 */
	protected byte[] createRequestAuthenticator(String sharedSecret) {
		byte[] secretBytes = RadiusUtil.getUtf8Bytes(sharedSecret);
		byte[] randomBytes = new byte[16];
		random.nextBytes(randomBytes);    	

		MessageDigest md5 = getMd5Digest();
		md5.reset();
       	md5.update(secretBytes);
       	md5.update(randomBytes);
		return md5.digest();
	}
	
	/**
	 * AccountingRequest overrides this
	 * method to create a request authenticator as specified by RFC 2866.		 
	 * @param sharedSecret shared secret
	 * @param packetLength length of the final Radius packet
	 * @param attributes attribute data
	 * @return new request authenticator
	 */
	protected byte[] updateRequestAuthenticator(String sharedSecret, int packetLength, byte[] attributes) {
		return authenticator;
	}
	
	/**
	 * Creates an authenticator for a Radius response packet.
	 * @param sharedSecret shared secret
	 * @param packetLength length of response packet
	 * @param attributes encoded attributes of response packet
	 * @param requestAuthenticator request packet authenticator
	 * @return new 16 byte response authenticator
	 */
	protected byte[] createResponseAuthenticator(String sharedSecret, int packetLength, byte[] attributes, byte[] requestAuthenticator) {
		MessageDigest md5 = getMd5Digest();
		md5.reset();
        md5.update((byte)getPacketType());
        md5.update((byte)getPacketIdentifier());
        md5.update((byte)(packetLength >> 8));
        md5.update((byte)(packetLength & 0x0ff));
        md5.update(requestAuthenticator, 0, requestAuthenticator.length);
        md5.update(attributes, 0, attributes.length);
        md5.update(RadiusUtil.getUtf8Bytes(sharedSecret));
        return md5.digest();		
	}

	/**
	 * Reads a Radius packet from the given input stream and
	 * creates an appropiate RadiusPacket descendant object.
	 * Reads in all attributes and returns the object. 
	 * Decodes the encrypted fields and attributes of the packet.
	 * @param sharedSecret shared secret to be used to decode this packet
	 * @param request Radius request packet if this is a response packet to be 
	 * decoded, null if this is a request packet to be decoded
	 * @return new RadiusPacket object
	 * @exception IOException if an IO error occurred
	 * @exception RadiusException if the Radius packet is malformed
	 */
	protected static RadiusPacket decodePacket(InputStream in, String sharedSecret, RadiusPacket request) 
	throws IOException, RadiusException {
		// check shared secret
		if (sharedSecret == null || sharedSecret.length() == 0)
			throw new RuntimeException("no shared secret has been set");
	
		// check request authenticator
		if (request != null && request.getAuthenticator() == null)
			throw new RuntimeException("request authenticator not set");

		// read and check header
		int type = in.read();
		int identifier = in.read();
		int length = in.read() << 8 | in.read();
	
		if (request != null && request.getPacketIdentifier() != identifier)
			throw new RadiusException("bad packet: invalid packet identifier");
		if (length < RADIUS_HEADER_LENGTH)
			throw new RadiusException("bad packet: packet too short (" + length + " bytes)");
		if (length > MAX_PACKET_LENGTH)
			throw new RadiusException("bad packet: packet too long (" + length + " bytes)");
	
		// read rest of packet
		byte[] authenticator = new byte[16];
		byte[] attributeData = new byte[length - RADIUS_HEADER_LENGTH];
		in.read(authenticator);
		in.read(attributeData);
	
		// check and count attributes
		int pos = 0;
		int attributeCount = 0;
		while (pos < attributeData.length) {
			if (pos + 1 >= attributeData.length)
				throw new RadiusException("bad packet: attribute length mismatch");
			pos += attributeData[pos + 1] & 0x0ff;
			attributeCount++;
		}
		if (pos != attributeData.length)
			throw new RadiusException("bad packet: attribute length mismatch");
	
		// create RadiusPacket object; set properties
		RadiusPacket rp = createRadiusPacket(type);
		rp.setPacketType(type);
		rp.setPacketIdentifier(identifier);
		rp.authenticator = authenticator;
		
		// load attributes
		ArrayList attributes = new ArrayList(attributeCount);
		pos = 0;
		while (pos < attributeData.length) {
			int attributeType = attributeData[pos] & 0x0ff;
			int attributeLength = attributeData[pos + 1] & 0x0ff;
			RadiusAttribute a = RadiusAttribute.createRadiusAttribute(attributeType);
			a.readAttribute(attributeData, pos, attributeLength);
			rp.addAttribute(a);
			pos += attributeLength;
		}
		
		// request packet?
		if (request == null) {
			// decode attributes
			rp.decodeRequestAttributes(sharedSecret);
		} else {
			// response packet: check authenticator
			rp.checkResponseAuthenticator(sharedSecret, length, attributeData, request.getAuthenticator());
		}
		
		return rp;
	}
	
	/**
	 * Can be overriden to decode encoded request attributes such as
	 * User-Password. This method may use getAuthenticator() to get the
	 * request authenticator.
	 * @param sharedSecret
	 */
	protected void decodeRequestAttributes(String sharedSecret) 
	throws RadiusException {
	}
	
	/**
	 * This method checks the authenticator of this Radius packet. This method
	 * may be overriden to include special attributes in the authenticator check.
	 * @param sharedSecret shared secret to be used to encrypt the authenticator
	 * @param packetLength length of the response packet
	 * @param attributes attribute data of the response packet
	 * @param requestAuthenticator 16 bytes authenticator of the request packet belonging
	 * to this response packet
	 */
	protected void checkResponseAuthenticator(String sharedSecret, int packetLength, byte[] attributes, byte[] requestAuthenticator) 
	throws RadiusException {
		byte[] authenticator = createResponseAuthenticator(sharedSecret, packetLength, attributes, requestAuthenticator);
		byte[] receivedAuth = getAuthenticator();
		for (int i = 0; i < 16; i++)
			if (authenticator[i] != receivedAuth[i])
				throw new RadiusException("response authenticator invalid");
	}
	
	/**
	 * Returns a MD5 digest.
	 * @return MessageDigest object
	 */
	protected MessageDigest getMd5Digest() {
		if (md5Digest == null)
			try {
				md5Digest = MessageDigest.getInstance("MD5");
			} catch (NoSuchAlgorithmException nsae) {
				throw new RuntimeException("md5 digest not available", nsae);
			}
		return md5Digest;
	}

	/**
	 * Encodes the attributes of this Radius packet to a byte array.
	 * @return byte array with encoded attributes
	 * @throws IOException error writing data
	 */
	protected byte[] getAttributeBytes() 
	throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream(MAX_PACKET_LENGTH);
		for (Iterator i = attributes.iterator(); i.hasNext();) {
			RadiusAttribute a = (RadiusAttribute)i.next();
			bos.write(a.writeAttribute());
		}
		bos.flush();
		return bos.toByteArray();
	}

	/**
	 * Type of this Radius packet.
	 */
	private int packetType = 0;
		
	/**
	 * Identifier of this packet.
	 */
	private int packetIdentifier = 0;
		
	/**
	 * Attributes for this packet.
	 */
	private List attributes = new ArrayList();
	
	/**
	 * MD5 digest.
	 */
	private MessageDigest md5Digest = null;
	
	/**
	 * Authenticator for this Radius packet.
	 */
	private byte[] authenticator = null;
	
	/**
	 * Next packet identifier.
	 */
	private static int nextPacketId = 0;
	
	/**
	 * Random number generator.
	 */
	private static SecureRandom random = new SecureRandom();
	
}
