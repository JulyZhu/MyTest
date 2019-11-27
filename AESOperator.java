package util.AES;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class AESOperator {
	// 加密用的Key可以用26个字母和数字组成，此处使用AES-128-CBC加密模式，key需要为16位。
	// 合力系统使用AES加密算法时，默认偏移量IV和密钥sKey为同一个值。
	private String sKey = "123456789abcdefg";
	private String IV = "123456789abcdefg";
	private String TRANSFORMATION = "AES/CBC/PKCS5Padding";
	private String UTF8 = "utf-8";
	private String AES = "AES";

	// 加密方法
	public String encrypt(String sSrc) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(sKey.getBytes(this.UTF8), this.AES);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes(this.UTF8));
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParameterSpec);
		byte[] encrypted = cipher.doFinal(sSrc.getBytes(this.UTF8));
		return new BASE64Encoder().encode(encrypted);
	}

	// 解密方法
	public String decrypt(String sSrc) throws Exception {
		Cipher cipher = Cipher.getInstance(this.TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sKey.getBytes(this.UTF8), this.AES),
				new IvParameterSpec(IV.getBytes(this.UTF8)));
		return new String(cipher.doFinal(new BASE64Decoder().decodeBuffer(sSrc)), this.UTF8);

	}

	public static void main(String[] args) throws Exception {
		// 需要加密的字串
		String cSrc = "加密测试字段";
		System.out.println(cSrc);
		AESOperator aes = new AESOperator();
		// 加密
		long lStart = System.currentTimeMillis();
		String enString = aes.encrypt(cSrc);
		System.out.println("加密后的字串是：" + enString);

		long lUseTime = System.currentTimeMillis() - lStart;
		System.out.println("加密耗时：" + lUseTime + "毫秒");
		// 解密
		lStart = System.currentTimeMillis();
		String DeString = aes.decrypt(enString);
		System.out.println("解密后的字串是：" + DeString);
		lUseTime = System.currentTimeMillis() - lStart;
		System.out.println("解密耗时：" + lUseTime + "毫秒");
	}
}
