package com.bigohk.scalotip

import org.scalatest.FlatSpec

import scala.compat.Platform

class TOTPFunctionalTest extends FlatSpec {
  final val SEED = "" +
    "3132333435363738" +
    "3930313233343536" +
    "37383930"

  "TOTP" should "remain same within a 30s interval" in {

    val snapshot = Platform.currentTime
    val offset = 1000L
    val slotSize = 30000L

    val totp0 = HOTPTimeBased.generateTOTP(SEED, snapshot / slotSize, 6)
    val totp1 = HOTPTimeBased.generateTOTP(SEED, (snapshot + offset) / slotSize, 6)

    assert(totp0 === totp1)
  }

  it should "change after 30s interval" in {
    val snapshot = Platform.currentTime
    val offset = 31000L
    val slotSize = 30000L

    val totp0 = HOTPTimeBased.generateTOTP(SEED, snapshot / slotSize, 6)
    val totp1 = HOTPTimeBased.generateTOTP(SEED, (snapshot + offset) / slotSize, 6)

    assert(totp0 != totp1)
  }

}
