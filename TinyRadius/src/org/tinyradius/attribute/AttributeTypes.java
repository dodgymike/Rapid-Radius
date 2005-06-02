/**
 * $Id: AttributeTypes.java,v 1.2 2005/06/02 14:22:06 wuttke Exp $
 * Created on 08.04.2005
 * @author Matthias Wuttke
 * @version $Revision: 1.2 $
 */
package org.tinyradius.attribute;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * This class manages a dictionary of Radius attribute types.
 */
public class AttributeTypes {

	/**
	 * Gets an AttributeType object by looking up a Radius type code.
	 * @param type Radius attribute type code
	 * @return AttributeType object
	 */
    public static AttributeType getAttributeType(int type) {
    	if (type < 1 || type > 255)
    		throw new IllegalArgumentException("invalid attribute type");
    	return (AttributeType)attributeTypesByCode.get(new Integer(type));
    }
    
	/**
	 * Gets an AttributeType object by looking up a Radius type name.
	 * @param name Radius attribute type name
	 * @return AttributeType object
	 */
    public static AttributeType getAttributeType(String name) {
    	return (AttributeType)attributeTypesByName.get(name);
    }
    
    /**
     * Returns the type code for the attribute with the given name.
     * @param name attribute type name
     * @return attribute type code
     */
    public static int getAttributeTypeCode(String name) {
    	AttributeType at = getAttributeType(name);
    	if (at == null)
    		throw new IllegalArgumentException("attribute '" + name + "' not found");
    	return at.getTypeCode();
    }
    
    /**
     * Returns a VendorAttributeType object by looking up a vendor-specific
     * sub-attribute type code.
     * @param vendorId vendor ID
     * @param type vendor sub-attribute type code
     * @return VendorAttributeType object or null
     */
    public static AttributeType getVendorSpecificAttributeType(int vendorId, int type) {
    	String key = Integer.toString(vendorId) + "-" + Integer.toString(type);
    	return (AttributeType)attributeTypesByVendorCode.get(key);
    }
    
    /**
     * Attribute type hash, key: type name (String), value: AttributeType or VendorAttributeType
     */
    private static Map attributeTypesByName = new HashMap();
    
    /**
     * Attribute type hash, key: type code (Integer), value: AttributeType
     */
    private static Map attributeTypesByCode = new HashMap();
    
    /**
     * Attribute type hash, key: vendorId "-" code (String), value: VendorAttributeType
     */
    private static Map attributeTypesByVendorCode = new HashMap();

    /**
     * Reads in the dictionary.
     */
    static {
		String line;
		int lineNum = 0;
    	try {
    		// open dictionary resource
    		InputStream is = AttributeTypes.class.getClassLoader().getResourceAsStream("org/tinyradius/attribute/dictionary");
    		if (is == null)
    			throw new IOException("dictionary file not found");
    		
    		// read each line separately
    		BufferedReader in = new BufferedReader(new InputStreamReader(is));
    		while ((line = in.readLine()) != null) {
    			// ignore comments
    			lineNum++;
    			line = line.trim();
    			if (line.startsWith("#") || line.length() == 0)
    				continue;
    			
    			// tokenize line by whitespace
    			StringTokenizer tok = new StringTokenizer(line);
    			if (!tok.hasMoreTokens())
    				continue;
    			
    			String lineType = tok.nextToken().trim();
    			if (lineType.equalsIgnoreCase("ATTRIBUTE")) {
    				// line declares an attribute
        			if (tok.countTokens() != 3)
        				throw new IOException("syntax error on line " + lineNum);
    				
    				// read name, code, type
    				String name = tok.nextToken().trim();
    				int code = Integer.parseInt(tok.nextToken());
    				String typeStr = tok.nextToken().trim();

    				if (attributeTypesByName.containsKey(name))
    					throw new IOException("duplicate attribute name: " + name + ", line: " + lineNum);

    				// translate type to class
    				Class type;
    				if (code == VendorSpecificAttribute.VENDOR_SPECIFIC)
    					type = VendorSpecificAttribute.class;
    				else
    					type = getAttributeTypeClass(code, typeStr);
    				
    				// create and cache object
    				AttributeType at = new AttributeType(code, name, type);
    				attributeTypesByName.put(name, at);
    				attributeTypesByCode.put(new Integer(code), at);
    			} else if(lineType.equalsIgnoreCase("VALUE")) {
    				// line declares an attribute value (enumeration)
        			if (tok.countTokens() != 3)
        				throw new IOException("syntax error on line " + lineNum);

    				String typeName = tok.nextToken().trim();
    				String enumName = tok.nextToken().trim();
    				String valStr = tok.nextToken().trim();
    				AttributeType at = getAttributeType(typeName);
    				if (at == null)
    					throw new IOException("unknown attribute type: " + typeName + ", line: " + lineNum);
    				else
    					at.addEnumerationValue(Integer.parseInt(valStr), enumName);
    			} else if (lineType.equalsIgnoreCase("VENDORATTR")) {
    				// line declares a Vendor-Specific attribute
        			if (tok.countTokens() != 4)
        				throw new IOException("syntax error on line " + lineNum);
        			
    				String vendor = tok.nextToken().trim();
    				String name = tok.nextToken().trim();
    				int code = Integer.parseInt(tok.nextToken().trim());
    				String typeStr = tok.nextToken().trim();

    				if (attributeTypesByName.containsKey(name))
    					throw new IOException("duplicate attribute name: " + name + ", line: " + lineNum);

    				Class type = getAttributeTypeClass(code, typeStr);
    				
    				AttributeType at = new AttributeType(Integer.parseInt(vendor), code, name, type);
    				attributeTypesByName.put(name, at);
    				attributeTypesByVendorCode.put(vendor + "-" + code, at);
    			} else
    				throw new IOException("unknown line type: " + lineType + " line: " + lineNum);
    		}
    	} catch (IOException e) {
    		throw new RuntimeException("unable to read attribute dictionary", e);
    	}
    }
    
    /**
     * Returns the RadiusAttribute descendant class for the given
     * attribute type.
     * @param typeStr string|octets|integer|date|ipaddr
     * @return RadiusAttribute class or descendant
     */
    private static Class getAttributeTypeClass(int attributeType, String typeStr) {
		Class type = RadiusAttribute.class;
		if (typeStr.equalsIgnoreCase("string"))
			type = StringAttribute.class;
		else if (typeStr.equalsIgnoreCase("octets"))
			type = RadiusAttribute.class;
		else if (typeStr.equalsIgnoreCase("integer") || typeStr.equalsIgnoreCase("date"))
			type = IntegerAttribute.class;
		else if (typeStr.equalsIgnoreCase("ipaddr"))
			type = IpAttribute.class;
		return type;
    }
    
}
