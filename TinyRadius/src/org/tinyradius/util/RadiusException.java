/**
 * $Id: RadiusException.java,v 1.1 2005/04/17 14:51:33 wuttke Exp $
 * Created on 10.04.2005
 * @author Matthias Wuttke
 * @version $Revision: 1.1 $
 */
package org.tinyradius.util;

/**
 * An exception which occurs on Radius protocol errors like
 * invalid packets or malformed attributes.
 */
public class RadiusException extends Exception {

	/**
	 * Constructs a RadiusException with a message.
	 * @param message error message
	 */
	public RadiusException(String message) {
		super(message);
	}
	
}
