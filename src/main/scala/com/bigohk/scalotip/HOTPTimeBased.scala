package com.bigohk.scalotip

import java.lang.reflect.UndeclaredThrowableException
import java.math.BigInteger
import java.security.GeneralSecurityException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object HOTPTimeBased {

  private def hmac_sha(crypto: String, keyBytes: Array[Byte], text: Array[Byte]) :Array[Byte] = try {
    val hmac = Mac.getInstance(crypto)
    val macKey = new SecretKeySpec(keyBytes, "RAW")
    hmac.init(macKey)
    hmac.doFinal(text)
  } catch {
    case gse: GeneralSecurityException =>
      throw new UndeclaredThrowableException(gse)
  }

  private def hexStr2Bytes(hex: String) :Array[Byte] = {
    // Adding one byte to get the right conversion
    // Values starting with "0" can be converted
    val bArray = new BigInteger("10" + hex, 16).toByteArray

    // Copy all the REAL bytes, not the "first"
    val ret = new Array[Byte](bArray.length - 1)
    var i = 0
    while (i < ret.length) {
      ret(i) = bArray(i + 1)
      i += 1
    }
    ret
  }

  private val DIGITS_POWER =
    //    0  1   2    3     4      5       6        7         8
    Array(1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000)


  def generateTOTP(key: String, slot: BigInt, returnDigits: Int): String = generateTOTP2(key, slot, returnDigits, "HmacSHA1")
  def generateTOTP256(key: String, slot: BigInt, returnDigits: Int): String = generateTOTP2(key, slot, returnDigits, "HmacSHA256")
  def generateTOTP512(key: String, slot: BigInt, returnDigits: Int): String = generateTOTP2(key, slot, returnDigits, "HmacSHA512")
  private def generateTOTP2(seed: String, slot: BigInt, returnDigits: Int, crypto: String): String = {
    val hash = hmac_sha(crypto, hexStr2Bytes(seed), slot.toByteArray.reverse.padTo(8, 0.toByte).reverse)
    val offset = hash(hash.length - 1) & 0xf
    val binary =
      ((hash(offset + 0) & 0x7f) << 24) |
        ((hash(offset + 1) & 0xff) << 16) |
        ((hash(offset + 2) & 0xff) << 8) |
        ((hash(offset + 3) & 0xff) << 0)

    val otp = binary % DIGITS_POWER(returnDigits)

    otp.toString.reverse.padTo(returnDigits, '0').reverse
  }

}
