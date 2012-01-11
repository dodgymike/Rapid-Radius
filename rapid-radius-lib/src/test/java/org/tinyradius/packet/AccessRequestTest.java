package org.tinyradius.packet;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;

import net.sf.jradius.util.RadiusUtils;

import org.junit.Test;
import org.tinyradius.attribute.StringAttribute;
import org.tinyradius.util.RadiusException;

import com.entersectmobile.util.StringTools;

public class AccessRequestTest {
	@Test
	public void it_correctly_generates_mschapv2_responses()
			throws RadiusException {
		String username = "gerhard";
		String password = "test12345";

		/*
		 * byte[] authenticatorChallenge = new byte[] { 0x54, 0x6c, (byte) 0xa8,
		 * (byte) 0x9c, 0x30, 0x36, 0x49, (byte) 0xcf, 0x30, 0x2d, (byte) 0x89,
		 * 0x79, (byte) 0x99, (byte) 0xcc, 0x70, (byte) 0xa0 };
		 * 
		 * byte[] responseData = new byte[] { 0x01, 0x00, (byte) 0xa6, (byte)
		 * 0xef, 0x7d, (byte) 0xcd, (byte) 0xf2, (byte) 0xcf, (byte) 0x82, 0x53,
		 * 0x24, 0x5b, 0x18, (byte) 0x96, 0x42, 0x3f, (byte) 0xe2, (byte) 0xde,
		 * 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xf1, (byte)
		 * 0x81, 0x28, (byte) 0xf1, (byte) 0xd7, (byte) 0xdc, (byte) 0x91, 0xc,
		 * 0x0b, 0x60, (byte) 0xc8, 0x58, 0x22, 0x1f, 0x6b, (byte) 0xdd, (byte)
		 * 0xb0, (byte) 0x84, 0x4a, (byte) 0x9c, 0x0b, 0x24, (byte) 0xdb, (byte)
		 * 0x42a };
		 */

		/*
		 * Freeradius username: gerhard 
		 * ntresponse:
		 * {0xF,0x28,0x7D,0x8A,0x1,0xFA,
		 * 0x7D,0xD6,0x99,0x60,0xBC,0xA8,0xB0,0xB2,0x37
		 * ,0xD7,0xCB,0x16,0xA,0x73,0x5D,0x8B,0xBB,0xE0,} 
		 * nt_hash_hash: {0xCB,
		 * 0xBE, 0xD6, 0x86, 0x4, 0x2E, 0x79, 0x4F, 0x17, 0xCD, 0xA4, 0xB9,
		 * 0xC5, 0x4F, 0x34, 0x87, } 
		 * peer_challenge: {0x37, 0xE4, 0x60, 0x2,
		 * 0x74, 0xF7, 0x9D, 0xEA, 0x3B, 0xC1, 0xFF, 0xF8, 0xA2, 0xD0, 0x19,
		 * 0x7E, } 
		 * auth_challenge: {0x79, 0xDA, 0xF7, 0x77, 0xD1, 0xFC, 0x7,
		 * 0x45, 0x32, 0xA5, 0x65, 0x7, 0x4C, 0x9D, 0xBC, 0x92, } 
		 * challenge:
		 * {0xB, 0x20, 0tx66, 0xB9, 0xF5, 0x7E, 0x63, 0xC5, } 
		 * response: {0x53,
		 * 0x3D, 0x32, 0x39, 0x42, 0x45, 0x36, 0x46, 0x36, 0x32, 0x42, 0x46,
		 * 0x44, 0x32, 0x45, 0x43, 0x38, 0x38, 0x34, 0x42, 0x39, 0x36, 0x39,
		 * 0x36, 0x35, 0x43, 0x39, 0x43, 0x39, 0x39, 0x45, 0x37, 0x46, 0x35,
		 * 0x32, 0x38, 0x46, 0x44, 0x37, 0x42, 0x38, 0x30, }
		 */

		byte[] authenticatorChallenge = {(byte)0x84, (byte)0x9B, (byte)0x32, (byte)0xDD, (byte)0xFB, (byte)0x96, (byte)0x0, (byte)0x95, (byte)0x17, (byte)0x32, (byte)0x7D, (byte)0x3C, (byte)0x2D, (byte)0x33, (byte)0x63, (byte)0x5A, };

		// Challenge: 0x546ca89c303649cf302d897999cc70a0
		// response:
		// 0x0100a6ef7dcdf2cf8253245b1896423fe2de0000000000000000f18128f1d7dc91c0b60c858221f6bddb0844a9c0b24db42a

		// Sent: S=04F8B79BCEB7825B2D669E110E44FF3ED3D5FD3B

		// RAS rx: 04 F8 B7 9B CE B7 82 5B 2D 66 9E 11 0E 44 FF 3E D3 D5 FD 3B
		// RAS ex: 5B E6 60 E6 37 7F 70 C9 72 19 59 E2 C8 BE FD 11 FB 8D A6 B4

		// System.err.println(RadiusUtils.byteArrayToHexString(responseData));

		AccessRequest accessRequest = new AccessRequest();

		byte ident = 0x01;

		// List<byte[]> responseComponents =
		// accessRequest.decodeMSCHAPV2Response(responseData);
		// byte[] ntResponse = responseComponents.get(0);
		byte[] ntResponse = {(byte)0x8D,(byte)0xF1,(byte)0x2E,(byte)0xAE,(byte)0x74,(byte)0x7,(byte)0xEB,(byte)0x6A,(byte)0x31,(byte)0x58,(byte)0x16,(byte)0x2A,(byte)0xB0,(byte)0x7F,(byte)0xDD,(byte)0x98,(byte)0xDC,(byte)0x84,(byte)0xAA,(byte)0x80,(byte)0xB8,(byte)0x5F,(byte)0x96,(byte)0x9E,};
		
		System.err.println("ntResponse ("
				+ RadiusUtils.byteArrayToHexString(ntResponse) + ")");
		// byte[] peerChallenge = responseComponents.get(1);
		byte[] peerChallenge =  {(byte)0x45, (byte)0xC1, (byte)0x27, (byte)0x66, (byte)0x91, (byte)0x19, (byte)0x68, (byte)0xA5, (byte)0x1F, (byte)0xD3, (byte)0x8C, (byte)0xA8, (byte)0xD1, (byte)0x6F, (byte)0x7F, (byte)0xA4, };
		System.err.println("peerChallenge ("
				+ RadiusUtils.byteArrayToHexString(peerChallenge) + ")");

		String mschapResponse = accessRequest.createMSCHAPV2Response(username,
				password.getBytes(), ident, ntResponse, peerChallenge,
				authenticatorChallenge);

		byte[] expectedDigest = {(byte)0xDB, (byte)0x28, (byte)0xF4, (byte)0xEC, (byte)0x5E, (byte)0xD9, (byte)0x3, (byte)0x2A, (byte)0x40, (byte)0x75, (byte)0xEB, (byte)0x31, (byte)0x22, (byte)0xB6, (byte)0x69, (byte)0xA6, (byte)0x9B, (byte)0x7E, (byte)0xE1, (byte)0xCC, };
		System.err.println("expectedDigest (" + StringTools.toHexString(expectedDigest) + ")");
		
		System.err.println("mschapResponse (" + mschapResponse + ")");
		System.err.println("mschapResponse 2 (" + StringTools.toHexString(mschapResponse) + ")");

		byte[] response = {0x01, 0x53, 0x3D, 0x44, 0x42, 0x32, 0x38, 0x46, 0x34, 0x45, 0x43, 0x35, 0x45, 0x44, 0x39, 0x30, 0x33, 0x32, 0x41, 0x34, 0x30, 0x37, 0x35, 0x45, 0x42, 0x33, 0x31, 0x32, 0x32, 0x42, 0x36, 0x36, 0x39, 0x41, 0x36, 0x39, 0x42, 0x37, 0x45, 0x45, 0x31, 0x43, 0x43, };
		System.err.println("response (" + RadiusUtils.byteArrayToHexString(response) + ")");
		
//		assertEquals(RadiusUtils.byteArrayToHexString(response).toUpperCase(), mschapResponse);
	}
	
	@Test
	public void it_generates_the_correct_bytes() {
		String ePolicy = new String(new byte[] { 0x00 , 0x00 , 0x00 , 0x01 });
		
		byte[] compareBytes = { 0x00, 0x00, 0x00, 0x01 };
		
		assertEquals(compareBytes.length, ePolicy.getBytes().length);
		
		for(int i = 0; i < compareBytes.length; i++) {
			assertEquals(compareBytes[i], ePolicy.getBytes()[i]);
		}
	}
	
}
	
/*
	Service-Type = Framed-User
		06 06  00 00 00 02 
	Framed-Protocol = PPP
		07 06  00 00 00 01 
	Framed-IP-Address = 172.30.1.23
		08 06  ac 1e 01 17 
	Framed-Routing = Broadcast-Listen
		0a 06  00 00 00 03 
	Framed-Filter-Id = "std.ppp"
		0b 09  73 74 64 2e 70 70 70 
	Framed-MTU = 1500
		0c 06  00 00 05 dc 
	Framed-Compression = Van-Jacobson-TCP-IP
		0d 06  00 00 00 01 
	MS-CHAP2-Success = 0x01533d36333335443745324444323741423636434644334238334445424241364237363443323334343742
		1a 2d  01 53 3d 36 33 33 35 44 37 45 32 44 44 32 37 41 
			42 36 36 43 46 44 33 42 38 33 44 45 42 42 41 36 
			42 37 36 34 43 32 33 34 34 37 42 
		1a 06  00000137 (311)  1a 2d 01 53 3d 36 33 33 35 44 37 45 32 44 44 32 
			37 41 42 36 36 43 46 44 33 42 38 33 44 45 42 42 
			41 36 42 37 36 34 43 32 33 34 34 37 42 
	MS-MPPE-Recv-Key = 0x4ab23c4820120c37c04fbae1d25f5355
		11 24  82 1f 79 3c 78 ea 0c 2c 31 67 7c 57 85 15 93 08 
			af 49 fb 8c b8 fb c5 1e 6a ba 40 a5 fe fd 9e 70 
			2b 04 
		1a 06  00000137 (311)  11 24 82 1f 79 3c 78 ea 0c 2c 31 67 7c 57 85 15 
			93 08 af 49 fb 8c b8 fb c5 1e 6a ba 40 a5 fe fd 
			9e 70 2b 04 
	MS-MPPE-Send-Key = 0xd94362cfd43e001b5a3f493e2a1e9da4
		10 24  88 5e 05 6f 93 f4 e2 4f 41 80 c7 9e a5 9e 36 5f 
			67 d5 8e a8 49 36 ff 18 30 78 f8 2f 1e 9b 74 e2 
			75 37 
		1a 06  00000137 (311)  10 24 88 5e 05 6f 93 f4 e2 4f 41 80 c7 9e a5 9e 
			36 5f 67 d5 8e a8 49 36 ff 18 30 78 f8 2f 1e 9b 
			74 e2 75 37 
	MS-MPPE-Encryption-Policy = Encryption-Allowed
		07 06  00 00 00 01 
		1a 06  00000137 (311)  07 06 00 00 00 01 
	MS-MPPE-Encryption-Types = RC4-40or128-bit-Allowed
		08 06  00 00 00 06 
		1a 06  00000137 (311)  08 06 00 00 00 06 

 */

/*
Vendor-Specific: MS (311)
  MS-CHAP2-Success: S=A012B7E2233960864D475C91EE87EB941A9A89A6
Vendor-Specific: MS (311)
  MS-MPPE-Encryption-Policy: 0001
Vendor-Specific: MS (311)
  MS-MPPE-Encryption-Type: 0006
Vendor-Specific: MS (311)
  MS-MPPE-Send-Key: 9B0D2CF6A953E86D69B6B8E01389F3B1
Vendor-Specific: MS (311)
  MS-MPPE-Recv-Key: 022F36C8FB29A4181E58CB5F0C59B599
  					4ab23c4820120c37c04fbae1d25f5355
Framed-IP-Address: 172.30.1.22|#]

 */

/*
 * 
 * [#|2012-01-06T14:43:58.447+0200|INFO|glassfish3.1.1|org.tinyradius.util.
 * RadiusServer|_ThreadID=40;_ThreadName=Thread-2;|received packet from
 * router1-interconnect.entersect.co.za/172.30.30.1:45302 on local address
 * 0.0.0.0/0.0.0.0:7318: Access-Request, ID 79 Service-Type: Framed-User
 * Framed-Protocol: PPP NAS-Port: 814 NAS-Port-Type: Virtual User-Name: gerhard
 * Calling-Station-Id: 172.30.11.211 Called-Station-Id: 172.30.30.1
 * Vendor-Specific: MS (311) MS-CHAP-Challenge:
 * 0x1b3fbf2b0cf2ae1f4099e453f84ae9a9 Vendor-Specific: MS (311)
 * 
 * MS-CHAP2-Response:
 * 0x01000c16cb03e1043ddb3bca4d363c0dfc850000000000000000d5fc2c2b1b740ef2cd490a1b0b8c2942d58062cacd5e594d
 * NAS-Identifier: Router1 NAS-IP-Address: 172.30.30.1|#]
 */
