/**
 * $Id: VendorAttributeType.java,v 1.1 2005/04/17 14:51:33 wuttke Exp $
 * Created on 10.04.2005
 * @author Matthias Wuttke
 * @version $Revision: 1.1 $
 */
package org.tinyradius.attribute;

/**
 * Represents the type of the sub-attribute from a Vendor-Specific attribute.
 */
public class VendorAttributeType extends AttributeType {
	
	/**
	 * Constructs a Vendor-Specific sub-attribute type.
	 * @param vendor vendor ID
	 * @param code sub-attribute type
	 * @param name sub-attribute name
	 * @param type sub-attribute class
	 */
	public VendorAttributeType(int vendor, int code, String name, Class type) {
		super(code, name, type);
		setVendorId(vendor);
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
	 * @param vendorId vendor ID
	 */
	public void setVendorId(int vendorId) {
		this.vendorId = vendorId;
	}
	
	private int vendorId;

}
