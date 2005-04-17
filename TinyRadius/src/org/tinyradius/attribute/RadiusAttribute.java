/**
 * $Id: RadiusAttribute.java,v 1.1 2005/04/17 14:51:33 wuttke Exp $
 * Created on 07.04.2005
 * Released under the terms of the LGPL
 * @author Matthias Wuttke
 * @version $Revision: 1.1 $
 */
package org.tinyradius.attribute;

import org.tinyradius.util.RadiusException;
import org.tinyradius.util.RadiusUtil;

/**
 * This class represents a generic Radius attribute. Subclasses implement
 * methods to access the fields of special attributes.
 */
public class RadiusAttribute {

	/**
	 * Constructs an empty Radius attribute.
	 */
	public RadiusAttribute() {	
	}
	
	/**
	 * Constructs a Radius attribute with the specified
	 * type and data.
	 * @param type attribute type, see AttributeTypes.*
	 * @param data attribute data
	 */
	public RadiusAttribute(int type, byte[] data) {
		setAttributeType(type);
		setAttributeData(data);
	}
	
	/**
	 * Returns the data for this attribute.
	 * @return attribute data
	 */
	public byte[] getAttributeData() {
		return attributeData;
	}
	
	/**
	 * Sets the data for this attribute.
	 * @param attributeData attribute data
	 */
	public void setAttributeData(byte[] attributeData) {
		if (attributeData == null)
			throw new NullPointerException("attribute data is null");
		this.attributeData = attributeData;
	}

	/**
	 * Returns the type of this Radius attribute.
	 * @return type code, 0-255
	 */
	public int getAttributeType() {
		return attributeType;
	}
	
	/**
	 * Sets the type of this Radius attribute.
	 * @param attributeType type code, 0-255
	 */
	public void setAttributeType(int attributeType) {
		if (attributeType < 0 || attributeType > 255)
			throw new IllegalArgumentException("attribute type invalid: " + attributeType);
		this.attributeType = attributeType;
		setAttributeTypeObject(AttributeTypes.getAttributeType(attributeType));
	}
	
	/**
	 * Returns the AttributeType object for the type of this attribute.
	 * @return AttributeType object
	 */
	public AttributeType getAttributeTypeObject() {
		return typeObject;
	}
	
	/**
	 * Sets the AttributeType object for the type of this attribute.
	 * @param t AttributeType object
	 */
	public void setAttributeTypeObject(AttributeType t) {
		this.typeObject = t;
	}

	/**
	 * Sets the value of the attribute using a string.
	 * @param value value as a string
	 */
	public void setAttributeValue(String value) {
		throw new RuntimeException("cannot set the value of attribute " + attributeType + " as a string");
	}
	
	/**
	 * Gets the value of this attribute as a string.
	 * @return value
	 * @exception RadiusException if the value is invalid
	 */
	public String getAttributeValue() {
		return RadiusUtil.getHexString(getAttributeData());
	}
	
	/**
	 * Returns this attribute encoded as a byte array.
	 * @return attribute
	 */
	public byte[] writeAttribute() {
		if (getAttributeType() == -1)
			throw new IllegalArgumentException("attribute type not set");
		if (attributeData == null)
			throw new NullPointerException("attribute data not set");
		
		byte[] attr = new byte[2 + attributeData.length];
		attr[0] = (byte)getAttributeType();
		attr[1] = (byte)(2 + attributeData.length);
		System.arraycopy(attributeData, 0, attr, 2, attributeData.length);
		return attr;
	}
	
	/**
	 * Reads in this attribute from the passed byte array.
	 * @param data
	 */
	public void readAttribute(byte[] data, int offset, int length) 
	throws RadiusException {
		if (length < 2)
			throw new RadiusException("attribute length too small: " + length);
		int attrType = data[offset];
		int attrLen = data[offset + 1];
		byte[] attrData = new byte[attrLen - 2];
		System.arraycopy(data, offset + 2, attrData, 0, attrLen - 2);
		setAttributeType(attrType);
		setAttributeData(attrData);
	}
	
	/**
	 * String representation for debugging purposes.
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return typeObject.getName() + ": " + getAttributeValue();
	}
	
	/**
	 * Creates a RadiusAttribute object of the appropriate type.
	 * @param type attribute type
	 * @return RadiusAttribute object
	 */
	public static RadiusAttribute createRadiusAttribute(int type) {
		AttributeType at = AttributeTypes.getAttributeType(type);
		try {
			RadiusAttribute attribute = (RadiusAttribute)at.getType().newInstance();
			attribute.setAttributeType(type);
			return attribute;
		} catch (InstantiationException e) {
			// use generic class instead
			return new RadiusAttribute();
		} catch (IllegalAccessException f) {
			// use generic class instead
			return new RadiusAttribute();
		}
		
	}
	
	/**
	 * Attribute type
	 */
	private int attributeType = -1;
	
	/**
	 * Attribute data
	 */
	private byte[] attributeData = null;
	
	/**
	 * Attribute type object, may be null!
	 */
	private AttributeType typeObject = null;
	
}
