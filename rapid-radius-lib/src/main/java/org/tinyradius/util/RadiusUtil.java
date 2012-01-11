/**
 * $Id: RadiusUtil.java,v 1.2 2006/11/06 19:32:06 wuttke Exp $
 * Created on 09.04.2005
 * @author Matthias Wuttke
 * @version $Revision: 1.2 $
 */
package org.tinyradius.util;

import gnu.crypto.hash.HashFactory;
import gnu.crypto.hash.IMessageDigest;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * This class contains miscellaneous static utility functions.
 */
public class RadiusUtil {
	static byte magic1[] = new byte[] { 0x54, 0x68, 0x69, 0x73, 0x20, 0x69,
			0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20,
			0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79 };

	static byte magic2[] = new byte[] { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64,
			0x65, 0x2c, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
			0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65,
			0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
			0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c,
			0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
			0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x6b, 0x65, 0x79,
			0x2e };

	static byte magic3[] = new byte[] { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64,
			0x65, 0x2c, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
			0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65,
			0x20, 0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
			0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69,
			0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74,
			0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
			0x2e };

	static byte SHSpad1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	static byte SHSpad2[] = { (byte) 0xf2, (byte) 0xf2, (byte) 0xf2,
			(byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2,
			(byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2,
			(byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2,
			(byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2,
			(byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2,
			(byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2,
			(byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2, (byte) 0xf2,
			(byte) 0xf2, (byte) 0xf2 };

	/**
	 * Random number generator.
	 */
	private static SecureRandom random = new SecureRandom();

	/**
	 * Returns the passed string as a byte array containing the string in UTF-8
	 * representation.
	 * 
	 * @param str
	 *            Java string
	 * @return UTF-8 byte array
	 */
	public static byte[] getUtf8Bytes(String str) {
		try {
			return str.getBytes("UTF-8");
		} catch (UnsupportedEncodingException uee) {
			return str.getBytes();
		}
	}

	/**
	 * Creates a string from the passed byte array containing the string in
	 * UTF-8 representation.
	 * 
	 * @param utf8
	 *            UTF-8 byte array
	 * @return Java string
	 */
	public static String getStringFromUtf8(byte[] utf8) {
		try {
			return new String(utf8, "UTF-8");
		} catch (UnsupportedEncodingException uee) {
			return new String(utf8);
		}
	}

	/**
	 * Returns the byte array as a hex string in the format "0x1234".
	 * 
	 * @param data
	 *            byte array
	 * @return hex string
	 */
	public static String getHexString(byte[] data) {
		StringBuffer hex = new StringBuffer("0x");
		if (data != null)
			for (int i = 0; i < data.length; i++) {
				String digit = Integer.toString(data[i] & 0x0ff, 16);
				if (digit.length() < 2)
					hex.append('0');
				hex.append(digit);
			}
		return hex.toString();
	}

	public static byte[] concatenateByteArrays(byte a[], byte b[]) {
		byte rv[] = new byte[a.length + b.length];

		System.arraycopy(a, 0, rv, 0, a.length);
		System.arraycopy(b, 0, rv, a.length, b.length);

		return rv;
	}

	/**
	 * Generate the MPPE Master key
	 */
	public static byte[] generateMPPEMasterKey(byte[] ntHashHash,
			byte[] ntResponse) {
		IMessageDigest md = HashFactory.getInstance("SHA-1");

		md.update(ntHashHash, 0, ntHashHash.length);
		md.update(ntResponse, 0, ntResponse.length);
		md.update(magic1, 0, magic1.length);

		byte[] digest = md.digest();

		byte[] rv = new byte[16];
		System.arraycopy(digest, 0, rv, 0, 16);

		return rv;
	}

	/**
	 * Generate the MPPE AssymetricStartKey
	 */
	public static byte[] generateMPPEAssymetricStartKey(byte[] masterKey,
			int keyLength, boolean isSend) {
		byte[] magic = (isSend) ? magic3 : magic2;

		IMessageDigest md = HashFactory.getInstance("SHA-1");

		md.update(masterKey, 0, 16);
		md.update(SHSpad1, 0, 40);
		md.update(magic, 0, 84);
		md.update(SHSpad2, 0, 40);

		byte[] digest = md.digest();

		byte[] rv = new byte[keyLength];
		System.arraycopy(digest, 0, rv, 0, keyLength);

		return rv;
	}

	public static byte[] mppeCHAP2GenKeySend128(byte[] ntHashHash,
			byte[] ntResponse) {
		byte[] masterKey = generateMPPEMasterKey(ntHashHash, ntResponse);

		return generateMPPEAssymetricStartKey(masterKey, 16, true);
	}

	public static byte[] mppeCHAP2GenKeyRecv128(byte[] ntHashHash,
			byte[] ntResponse) {
		byte[] masterKey = generateMPPEMasterKey(ntHashHash, ntResponse);

		return generateMPPEAssymetricStartKey(masterKey, 16, false);
	}

	public static byte[] make_tunnel_passwd(byte[] input, int room, byte[] secret, byte[] vector) {
		final int authVectorLength = 16;
		final int authPasswordLength = authVectorLength;
		final int maxStringLength = 254;

		// NOTE This could be dodgy!
		int saltOffset = 0;

		// byte digest[] = new byte[authVectorLength];
		byte passwd[] = new byte[maxStringLength + authVectorLength];
		int len;

		/*
		 * Be paranoid.
		 */
		if (room > 253)
			room = 253;

		/*
		 * Account for 2 bytes of the salt, and round the room available down to
		 * the nearest multiple of 16. Then, subtract one from that to account
		 * for the length byte, and the resulting number is the upper bound on
		 * the data to copy.
		 * 
		 * We could short-cut this calculation just be forcing inlen to be no
		 * more than 239. It would work for all VSA's, as we don't pack multiple
		 * VSA's into one attribute.
		 * 
		 * However, this calculation is more general, if a little complex. And
		 * it will work in the future for all possible kinds of weird attribute
		 * packing.
		 */
		room -= 2;
		room -= (room & 0x0f);
		room--;

		int inlen = input.length;
		
		if (inlen > room)
			inlen = room;

		/*
		 * Length of the encrypted data is password length plus one byte for the
		 * length of the password.
		 */
		len = inlen + 1;
		if ((len & 0x0f) != 0) {
			len += 0x0f;
			len &= ~0x0f;
		}

		/*
		 * Copy the password over.
		 */
		System.arraycopy(input, 0, passwd, 3, inlen);
		// memcpy(passwd + 3, input, inlen);
		for (int i = 3 + inlen; i < passwd.length - 3 - inlen; i++) {
			passwd[i] = 0;
		}
		// memset(passwd + 3 + inlen, 0, passwd.length - 3 - inlen);

		/*
		 * Generate salt. The RFC's say:
		 * 
		 * The high bit of salt[0] must be set, each salt in a packet should be
		 * unique, and they should be random
		 * 
		 * So, we set the high bit, add in a counter, and then add in some
		 * CSPRNG data. should be OK..
		 */
		passwd[0] = (byte) (0x80 | (((saltOffset++) & 0x0f) << 3) | (random.generateSeed(1)[0] & 0x07));
		passwd[1] = random.generateSeed(1)[0];
		passwd[2] = (byte) inlen; /* length of the password string */

		MessageDigest md5Digest = null;
		MessageDigest originalDigest = null;
		
		MessageDigest currentDigest = null;

		try {
			md5Digest = MessageDigest.getInstance("MD5");
			originalDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException nsae) {
			throw new RuntimeException("md5 digest not available", nsae);
		}

		md5Digest.update(secret);
		originalDigest.update(secret);

		currentDigest = md5Digest;

		md5Digest.update(vector, 0, authVectorLength);
		md5Digest.update(passwd, 0, 2);

		for (int n = 0; n < len; n += authPasswordLength) {
			if (n > 0) {
				currentDigest = originalDigest;

				currentDigest.update(passwd, 2 + n - authPasswordLength, authPasswordLength);
			}

			byte digest[] = currentDigest.digest();

			for (int i = 0; i < authPasswordLength; i++) {
				passwd[i + 2 + n] ^= digest[i];
			}
		}
		byte output[] = new byte[len + 2];
		System.arraycopy(passwd, 0, output, 0, len + 2);

		return output;
	}

	protected MessageDigest getMd5Digest() {
		MessageDigest md5Digest = null;

		try {
			md5Digest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException nsae) {
			throw new RuntimeException("md5 digest not available", nsae);
		}
		return md5Digest;
	}

	/**
	 * Generates an MS-MPPE-Recv-Key as per rfc2548
	 * 
	 * @return the recv key
	 */
	/*
	 * public static byte[] generateMPPEKey(String sharedSecret) { // generate a
	 * salt byte[] salt = random.generateSeed(2); // the leftmost bit of the
	 * SALT *must* be set salt[0] |= (byte)0x80;
	 * 
	 * // the key byte[] key = random.generateSeed(8);
	 * 
	 * // key plaintext is key length (1) + key (8) + padding (7) byte[]
	 * keyPlaintext = new byte[16]; // key length keyPlaintext[0] = 8; // copy
	 * the key for(int i = 0; i < 8; i++) { keyPlaintext[i + 1] = key[i]; } //
	 * padding for(int i = 9; i < 16; i++) { keyPlaintext[i] = 0x00; }
	 * 
	 * // MS-MPPE-Recv-Key = 0x228522099a3c68461bc731f135a9d551 //
	 * MS-MPPE-Send-Key = 0x01eb3af6d04c00e5f1d2cb76a4b6e967
	 * 
	 * // generate b(1) MessageDigest md5 = getMd5Digest(); md5.reset();
	 * md5.update(sharedSecret.getBytes()); md5.update(getAuthenticator());
	 * md5.update(salt);
	 * 
	 * byte[] b = new byte[16]; try { if(md5.digest(b, 0, 16) != 16) { throw new
	 * RuntimeException("Fatal exception generating recv key"); } } catch
	 * (DigestException e) { throw new
	 * RuntimeException("Fatal exception generating recv key", e); }
	 * 
	 * // XOR the results byte C[] = new byte[16];
	 * 
	 * for(int i = 0; i < 16; i++) { C[i] = (byte)(keyPlaintext[i] ^ b[i]); }
	 * 
	 * // make the full return buffer byte[] rv =
	 * RadiusUtil.concatenateByteArrays(salt, C);
	 * 
	 * return rv; }
	 */
}
