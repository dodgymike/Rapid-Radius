/**
 * $Id: AttributeType.java,v 1.1 2005/04/17 14:51:33 wuttke Exp $
 * Copyright by teuto.net Netzdienste GmbH 2005. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation. Commercial licenses also available.
 * See the accompanying file LICENSE for details.
 * @author Matthias Wuttke
 * @version $Revision: 1.1 $
 */
package org.tinyradius.attribute;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Represents a Radius attribute type.
 */
public class AttributeType {

	/**
	 * Create a new attribute type.
	 * @param code
	 * @param name
	 * @param type
	 */
	public AttributeType(int code, String name, Class type) {
		setCode(code);
		setName(name);
		setType(type);
	}
	
	/**
	 * Retrieves the Radius type code for this attribute type.
	 * @return Radius type code
	 */
	public int getCode() {
		return code;
	}
	
	/**
	 * Sets the Radius type code for this attribute type.
	 * @param code type code, 1-255
	 */
	public void setCode(int code) {
		if (code < 1 || code > 255)
			throw new IllegalArgumentException("code out of bounds");
		this.code = code;
	}
	
	/**
	 * Retrieves the name of this type.
	 * @return name
	 */
	public String getName() {
		return name;
	}
	
	/**
	 * Sets the name of this type.
	 * @param name type name
	 */
	public void setName(String name) {
		if (name == null || name.length() == 0)
			throw new IllegalArgumentException("name is empty");
		this.name = name;
	}
	
	/**
	 * Retrieves the RadiusAttribute descendant class which represents
	 * attributes of this type.
	 * @return class
	 */
	public Class getType() {
		return type;
	}
	
	/**
	 * Sets the RadiusAttribute descendant class which represents
	 * attributes of this type.
	 * @return class
	 */
	public void setType(Class type) {
		if (type == null)
			throw new NullPointerException("type is null");
		if (type.isInstance(RadiusAttribute.class))
			throw new IllegalArgumentException("type is not a RadiusAttribute descendant");
		this.type = type;
	}
	
	/**
	 * Returns the name of the given integer value if this attribute
	 * is an enumeration, or null if it is not or if the integer value
	 * is unknown. 
	 * @return name
	 */
	public String getEnumeration(int value) {
		if (enumeration != null)
			return (String)enumeration.get(new Integer(value));
		else
			return null;
	}
	
	/**
	 * Returns the number of the given string value if this attribute is
	 * an enumeration, or null if it is not or if the string value is unknown.
	 * @param value string value
	 * @return Integer or null
	 */
	public Integer getEnumeration(String value) {
		if (value == null || value.length() == 0)
			throw new IllegalArgumentException("value is empty");
		if (enumeration == null)
			return null;
		for (Iterator i = enumeration.entrySet().iterator(); i.hasNext();) {
			Map.Entry e = (Map.Entry)i.next();
			if (e.getValue().equals(value))
				return (Integer)e.getKey();
		}
		return null;
	}

	/**
	 * Adds a name for an integer value of this attribute.
	 * @param num number that shall get a name
	 * @param name the name for this number
	 */
	public void addEnumerationValue(int num, String name) {
		if (name == null || name.length() == 0)
			throw new IllegalArgumentException("name is empty");
		if (enumeration == null)
			enumeration = new HashMap();
		enumeration.put(new Integer(num), name);
	}
	
	private int code;
	private String name;
	private Class type;
	private Map enumeration = null;
	
}
