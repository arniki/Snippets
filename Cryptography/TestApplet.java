package appcrypto;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class TestApplet extends Applet {
	private KeyPair keypair;
	private RSAPublicKey pub;
	private Cipher rsa;
	public static void install(byte[] ba, short offset, byte len) {
		(new TestApplet()).register();
	}
	private TestApplet() {
	}
	public void process(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case (0x02): /* Generate Key RSA */
			if (keypair==null){
				if (keypair==null){
					keypair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
					keypair.genKeyPair();
					pub = (RSAPublicKey) keypair.getPublic();
					rsa = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
					rsa.init(keypair.getPrivate(), Cipher.MODE_DECRYPT);
				}
			}
			return;
		case (0x04): /* Retrieve e */
			short expLength = pub.getExponent(buf, ISO7816.OFFSET_CDATA);
			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, expLength);
			return;
		case (0x06): /* Retrieve N */
			short modLength = pub.getModulus(buf, ISO7816.OFFSET_CDATA);
			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, modLength);
			return;
			
		case (0x08): /* Receive encrypted data, decrypt and send back. Move P1, P2 one position further to make ciphertext continuous buffer*/
			
			apdu.setIncomingAndReceive();
			byte[] apduBuffer = apdu.getBuffer();
			byte[] decryptedBuffer = new byte[apduBuffer.length];
			Util.arrayFillNonAtomic(decryptedBuffer, (short) 0,
			        (short) decryptedBuffer.length, (byte) 0xAA);
			rsa.doFinal(apduBuffer, (short) 0, (short) apduBuffer.length, decryptedBuffer, (short) 0);

			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) decryptedBuffer.length);

			return;
		}
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);		
	}
}
