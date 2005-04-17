/**
 * $Id: VendorSpecificAttribute.java,v 1.1 2005/04/17 14:51:33 wuttke Exp $
 * Created on 10.04.2005
 * @author Matthias Wuttke
 * @version $Revision: 1.1 $
 */
package org.tinyradius.attribute;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.tinyradius.util.RadiusException;

/**
 * This class represents a "Vendor-Specific" attribute.
 */
public class VendorSpecificAttribute extends RadiusAttribute {

	/**
	 * Radius attribute type code for Vendor-Specific
	 */
	public static final int VENDOR_SPECIFIC = 26;
		
	/**
	 * Constructs an empty Vendor-Specific attribute that
	 * can be read from a Radius packet.
	 */
	public VendorSpecificAttribute() {
		super();
	}
	
	/**
	 * Constructs a new Vendor-Specific attribute to be sent.
	 * @param vendorId
	 */
	public VendorSpecificAttribute(int vendorId) {
		setAttributeType(VENDOR_SPECIFIC);
		setVendorId(vendorId);
	}
	
	/**
	 * Returns the vendor ID.
	 * @return vendor ID
	 */
	public int getVendorId() {
		return vendorId;
	}
	
	/**
	 * Sets the vendor ID.
	 * @param vendorId
	 */
	public void setVendorId(int vendorId) {
		this.vendorId = vendorId;
	}
	
	/**
	 * Adds a sub-attribute to this attribute.
	 * @param attribute sub-attribute to add
	 */
	public void addSubAttribute(RadiusAttribute attribute) {
		subAttributes.add(attribute);
	}
	
	/**
	 * Adds a sub-attribute with the specified name to this
	 * attribute.
	 * @param name name of the sub-attribute
	 * @param value value of the sub-attribute
	 * @exception IllegalArgumentException invalid sub-attribute name or value
	 */
	public void addSubAttribute(String name, String value) {
		if (name == null || name.length() == 0)
			throw new IllegalArgumentException("type name is empty");
		if (value == null || value.length() == 0)
			throw new IllegalArgumentException("value is empty");
		
		AttributeType type = AttributeTypes.getAttributeType(name);
		if (type == null)
			throw new IllegalArgumentException("unknown attribute type '" + name + "'");
		if (!(type instanceof VendorAttributeType))
			throw new IllegalArgumentException("attribute type '" + name + "' is not a Vendor-Specific sub-attribute");
		
		VendorAttributeType vat = (VendorAttributeType)type;
		if (vat.getVendorId() != getVendorId())
			throw new IllegalArgumentException("attribute type '" + name + "' does not belong to vendor ID " + getVendorId());

		RadiusAttribute attribute = createSubAttribute(getVendorId(), vat.getCode());
		attribute.setAttributeValue(value);
		addSubAttribute(attribute);		
	}
	
	/**
	 * Removes the specified sub-attribute from this attribute.
	 * @param attribute RadiusAttribute to remove
	 */
	public void removeSubAttribute(RadiusAttribute attribute) {
		if (!subAttributes.remove(attribute))
			throw new IllegalArgumentException("no such attribute");
	}
	
	/**
	 * Returns the list of sub-attributes.
	 * @return List of RadiusAttribute objects
	 */
	public List getSubAttributes() {
		return subAttributes;
	}
	
	/**
	 * Returns all sub-attributes of this attribut which have the given type.
	 * @param attributeType type of sub-attributes to get 
	 * @return list of RadiusAttribute objects, does not return null
	 */
	public List getSubAttributes(int attributeType) {
		if (attributeType < 1 || attributeType > 255)
			throw new IllegalArgumentException("sub-attribute type out of bounds");

		LinkedList result = new LinkedList();
		for (Iterator i = subAttributes.iterator(); i.hasNext();) {
			RadiusAttribute a = (RadiusAttribute)i.next();
			if (attributeType == a.getAttributeType())
				result.add(a);
		}
		return result;
	}
	
	/**
	 * Returns a sub-attribute of the given type which may only occur once
	 * in this attribute.
	 * @param type sub-attribute type
	 * @return RadiusAttribute object or null if there is no such sub-attribute
	 * @throws RuntimeException if there are multiple occurences of the
	 * requested sub-attribute type
	 */
	public RadiusAttribute getSubAttribute(int type) {
		List attrs = getSubAttributes(type);
		if (attrs.size() > 1)
			throw new RuntimeException("multiple sub-attributes of requested type " + type);
		else if (attrs.size() == 0)
			return null;
		else
			return (RadiusAttribute)attrs.get(0);
	}

	/**
	 * Returns a single sub-attribute of the given type name.
	 * @param type attribute type name
	 * @return RadiusAttribute object or null if there is no such attribute
	 * @throws RuntimeException if the attribute occurs multiple times
	 */
	public RadiusAttribute getSubAttribute(String type) 
	throws RadiusException {
		if (type == null || type.length() == 0)
			throw new IllegalArgumentException("type name is empty");
		
		AttributeType t = AttributeTypes.getAttributeType(type);
		if (t == null)
			throw new IllegalArgumentException("unknown attribute type name '" + type + "'");
		
		RadiusAttribute attr = getSubAttribute(t.getCode());
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
	public String getSubAttributeValue(String type) {
		if (type == null || type.length() == 0)
			throw new IllegalArgumentException("type name is empty");
		
		AttributeType t = AttributeTypes.getAttributeType(type);
		if (t == null)
			throw new IllegalArgumentException("unknown attribute type name '" + type + "'");
		
		RadiusAttribute attr = getSubAttribute(t.getCode());
		if (attr == null)
			return null;
		else
			return attr.getAttributeValue();
	}

	/**
	 * Renders this attribute as a byte array.
	 * @see org.tinyradius.attribute.RadiusAttribute#writeAttribute()
	 */
	public byte[] writeAttribute() {
		// write vendor ID
		ByteArrayOutputStream bos = new ByteArrayOutputStream(255);
		bos.write(vendorId >> 24 & 0x0ff);
		bos.write(vendorId >> 16 & 0x0ff);
		bos.write(vendorId >> 8 & 0x0ff);
		bos.write(vendorId & 0x0ff);
		
		// write sub-attributes
		try {
			for (Iterator i = subAttributes.iterator(); i.hasNext();) {
				RadiusAttribute a = (RadiusAttribute)i.next();
				bos.write(a.writeAttribute());
			}
		} catch (IOException ioe) {
			// occurs never
			throw new RuntimeException("error writing data", ioe);
		}
	
		// check data length
		byte[] attrData = bos.toByteArray();
		int len = attrData.length;
		if (len > 253)
			throw new RuntimeException("Vendor-Specific attribute too long: " + bos.size());
		
		// compose attribute
		byte[] attr = new byte[len + 2];
		attr[0] = VENDOR_SPECIFIC;	// code
		attr[1] = (byte)(len + 2);	// length
		System.arraycopy(attrData, 0, attr, 2, len);
		return attr;
	}
	
	/**
	 * Reads a Vendor-Specific attribute and decodes the internal sub-attribute
	 * structure. If it seems there is no such structure only the raw data is
	 * stored.
	 * @see org.tinyradius.attribute.RadiusAttribute#readAttribute(byte[], int, int)
	 */
	public void readAttribute(byte[] data, int offset, int length) 
	throws RadiusException {
		// check length
		if (length < 6)
			throw new RadiusException("Vendor-Specific attribute too short: " + length);
		
		int vsaCode = data[offset];
		int vsaLen = data[offset + 1] - 6;
		
		if (vsaCode != VENDOR_SPECIFIC)
			throw new RadiusException("not a Vendor-Specific attribute");
		
		// read vendor ID and vendor data
		vendorId = data[offset + 2] << 24 | data[offset + 3] << 16 | 
				   data[offset + 4] << 8 | data[offset + 5];
		
		// validate sub-attribute structure
		int pos = 0;
		int count = 0;
		while (pos < vsaLen) {
			if (pos + 1 >= vsaLen)
				throw new RadiusException("Vendor-Specific attribute malformed");
			int vsaSubType = data[(offset + 6) + pos] & 0x0ff;
			int vsaSubLen = data[(offset + 6) + pos + 1] & 0x0ff;
			pos += vsaSubLen;
			count++;
		}
		if (pos != vsaLen)
			throw new RadiusException("Vendor-Specific attribute malformed");
		
		subAttributes = new ArrayList(count);
		pos = 0;
		while (pos < vsaLen) {
			int subtype = data[(offset + 6) + pos] & 0x0ff;
			int sublength = data[(offset + 6) + pos + 1] & 0x0ff;
			VendorAttributeType vat = AttributeTypes.getVendorSpecificAttributeType(vendorId, subtype);
			RadiusAttribute a = createSubAttribute(vendorId, subtype);
			a.readAttribute(data, (offset + 6) + pos, sublength);
			a.setAttributeTypeObject(vat);
			subAttributes.add(a);
			pos += sublength;
		}
	}
	
	/**
	 * Returns a string representation for debugging.
	 * @see org.tinyradius.attribute.RadiusAttribute#toString()
	 */
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("Vendor-Specific: vendor ID ");
		sb.append(vendorId);
		for (Iterator i = getSubAttributes().iterator(); i.hasNext();) {
			RadiusAttribute attr = (RadiusAttribute)i.next();
			VendorAttributeType vat = AttributeTypes.getVendorSpecificAttributeType(getVendorId(), attr.getAttributeType());
			String value = attr.getAttributeValue();
			sb.append("\n  ");
			sb.append(vat.getName());
			sb.append(": ");
			sb.append(value);
		}
		return sb.toString();
	}
	
	/**
	 * Creates a new RadiusAttribute object meant to be used as a sub-attribute.
	 * @param vendorId vendor ID
	 * @param typeCode type code
	 * @return RadiusAttribute object
	 */
	public static RadiusAttribute createSubAttribute(int vendorId, int typeCode) {
		RadiusAttribute attribute = new RadiusAttribute();
		VendorAttributeType vat = AttributeTypes.getVendorSpecificAttributeType(vendorId, typeCode);
		if (vat != null && vat.getType() != null) {
			try {
				attribute = (RadiusAttribute)vat.getType().newInstance();
			} catch (Exception e) {}
		}
		
		attribute.setAttributeType(typeCode);
		if (vat != null)
			attribute.setAttributeTypeObject(vat);
		return attribute;
	}
	
	/**
	 * Vendor ID
	 */
	private int vendorId = 0;
	
	/**
	 * Sub attributes. Only set if isRawData == false.
	 */
	private List subAttributes = new ArrayList();
	
}