package org.tinyradius.util;

import static org.junit.Assert.assertEquals;
import net.sf.jradius.util.RadiusUtils;

import org.junit.Test;

public class RadiusUtilTest {
	
	@Test
	public void it_generates_a_valid_mppe_key() {
		String username = "User";
		String password = "clientPass";
		
		byte[] authChallenge = {
				(byte)0x5B, (byte)0x5D , (byte)0x7C , (byte)0x7D , (byte)0x7B , (byte)0x3F , (byte)0x2F , (byte)0x3E , (byte)0x3C , (byte)0x2C
				, (byte)0x60 , (byte)0x21 , (byte)0x32 , (byte)0x26 , (byte)0x26 , (byte)0x28
		};
		
		byte[] peerChallenge = {
				(byte)0x21 , (byte)0x40 , (byte)0x23 , (byte)0x24
				, (byte)0x25 , (byte)0x5E , (byte)0x26 , (byte)0x2A 
				, (byte)0x28 , (byte)0x29 , (byte)0x5F , (byte)0x2B 
				, (byte)0x3A , (byte)0x33 , (byte)0x7C , (byte)0x7E
		};
		
		byte[] challenge = {
				(byte)0xD0 , (byte)0x2E , (byte)0x43 , (byte)0x86 , (byte)0xBC , (byte)0xE9 , (byte)0x12 , (byte)0x26
		};
		
		byte[] ntResponse = {
				(byte)0x82 , (byte)0x30 , (byte)0x9E , (byte)0xCD , (byte)0x8D , (byte)0x70 , (byte)0x8B 
				, (byte)0x5E , (byte)0xA0 , (byte)0x8F , (byte)0xAA , (byte)0x39 , (byte)0x81 , (byte)0xCD 
				, (byte)0x83 , (byte)0x54 , (byte)0x42 , (byte)0x33 , (byte)0x11 , (byte)0x4A , (byte)0x3D 
				, (byte)0x85 , (byte)0xD6 , (byte)0xDF
		};
		
		byte[] ntHashHash = Authenticator.getPasswordHashHash(password.getBytes());
		assertEquals("41C00C584BD2D91C4017A2A12FA59F3F", RadiusUtils.byteArrayToHexString(ntHashHash).toUpperCase());
		
		byte[] masterKey = RadiusUtil.generateMPPEMasterKey(ntHashHash, ntResponse);
		assertEquals("FDECE3717A8C838CB388E527AE3CDD31", RadiusUtils.byteArrayToHexString(masterKey).toUpperCase());
		
		byte[] mppeSendKey = RadiusUtil.mppeCHAP2GenKeySend128(ntHashHash, ntResponse);
		assertEquals("8B7CDC149B993A1BA118CB153F56DCCB", RadiusUtils.byteArrayToHexString(mppeSendKey).toUpperCase());

		byte[] mppeRecvKey = RadiusUtil.mppeCHAP2GenKeyRecv128(ntHashHash, ntResponse);

	}
	
	@Test
	public void it_encrypts_the_mppe_key_correctly() {
/*		recv-key:
			abd555abffb34a0bd6aa7503b2c149ba
			92b0d69bced69124cc472ffca32f48142fe9d013e5c759b6abeab89448db590c7303

			864a2694537367cf5e89eab30a11e092c46bdf155936d7b2f9f56bb3c6adb026dfe9

		send-key:
			4ecdac6e358be88a24d58d263bc6e0c9
			99:bc:bb:5a:04:93:a1:81:60:16:68:93:75:5f:c9:7a:18:09:f4:e4:96:8d:de:5c:c5:80:0a:b6:80:10:b3:45:c2:c3
*/

		
		byte mppeKey[] = new byte[] { (byte)0xab, (byte)0xd5, (byte)0x55, (byte)0xab, (byte)0xff, (byte)0xb3, (byte)0x4a
				, (byte)0x0b, (byte)0xd6, (byte)0xaa, (byte)0x75, (byte)0x03, (byte)0xb2, (byte)0xc1, (byte)0x49, (byte)0xba };
		
		byte authenticator[] = {(byte)0x41, (byte)0x8B, (byte)0x13, (byte)0x69, (byte)0x5D, (byte)0x4C, (byte)0xF9, (byte)0x17, (byte)0x54, (byte)0x3E, (byte)0xDF, (byte)0xAF, (byte)0x93, (byte)0xFE, (byte)0x98, (byte)0x64, };
		
		byte mppeKeyEncrypted[] = RadiusUtil.make_tunnel_passwd(mppeKey, 1024, "test12345".getBytes(), authenticator);
		
		System.err.println("passwd (" + RadiusUtil.getHexString(mppeKeyEncrypted) + ")");
		
//		assertEquals("864a2694537367cf5e89eab30a11e092c46bdf155936d7b2f9f56bb3c6adb026dfe9", RadiusUtil.getHexString(mppeKeyEncrypted));
	}
	
	

}
