package com.bigohk.scalotip

import org.scalatest.FlatSpec

class TOTPVectors extends FlatSpec {
  "SHA1 TOTP vectors" should "be correct" in {
    val SEED = "" +
      "3132333435363738" +
      "3930313233343536" +
      "37383930"

    var totp = HOTPTimeBased.generateTOTP(SEED, 59L / 30L, 8)
    assert(totp === "94287082")

    totp = HOTPTimeBased.generateTOTP(SEED, 1111111109L / 30L, 8)
    assert(totp === "07081804")

    totp = HOTPTimeBased.generateTOTP(SEED, 1111111111L / 30L, 8)
    assert(totp === "14050471")

    totp = HOTPTimeBased.generateTOTP(SEED, 1234567890L / 30L, 8)
    assert(totp === "89005924")

    totp = HOTPTimeBased.generateTOTP(SEED, 2000000000L / 30L, 8)
    assert(totp === "69279037")

    totp = HOTPTimeBased.generateTOTP(SEED, 20000000000L / 30L, 8)
    assert(totp === "65353130")

  }

  "SHA256 TOTP vectors" should "be correct" in {
    val SEED = "" +
      "31323334353637383930313233343536" +
      "37383930313233343536373839303132"

    var totp = HOTPTimeBased.generateTOTP256(SEED, 59L / 30L, 8)
    assert(totp === "46119246")

    totp = HOTPTimeBased.generateTOTP256(SEED, 1111111109L / 30L, 8)
    assert(totp === "68084774")

    totp = HOTPTimeBased.generateTOTP256(SEED, 1111111111L / 30L, 8)
    assert(totp === "67062674")

    totp = HOTPTimeBased.generateTOTP256(SEED, 1234567890L / 30L, 8)
    assert(totp === "91819424")

    totp = HOTPTimeBased.generateTOTP256(SEED, 2000000000L / 30L, 8)
    assert(totp === "90698825")

    totp = HOTPTimeBased.generateTOTP256(SEED, 20000000000L / 30L, 8)
    assert(totp === "77737706")
  }

  "SHA512 TOTP vectors" should "be correct" in {
    val SEED = "" +
      "31323334353637383930313233343536" +
      "37383930313233343536373839303132" +
      "33343536373839303132333435363738" +
      "39303132333435363738393031323334"

    var totp = HOTPTimeBased.generateTOTP512(SEED, 59L / 30L, 8)
    assert(totp === "90693936")

    totp = HOTPTimeBased.generateTOTP512(SEED, 1111111109L / 30L, 8)
    assert(totp === "25091201")

    totp = HOTPTimeBased.generateTOTP512(SEED, 1111111111L / 30L, 8)
    assert(totp === "99943326")

    totp = HOTPTimeBased.generateTOTP512(SEED, 1234567890L / 30L, 8)
    assert(totp === "93441116")

    totp = HOTPTimeBased.generateTOTP512(SEED, 2000000000L / 30L, 8)
    assert(totp === "38618901")

    totp = HOTPTimeBased.generateTOTP512(SEED, 20000000000L / 30L, 8)
    assert(totp === "47863826")
  }
}
