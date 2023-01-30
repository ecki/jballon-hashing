/* jballoon-hashing
 *
 * Copyright 2023 by Bernd Eckenfels. Germany.
 *
 * Granted under Apache License 2.0.
 */
package net.eckenfels.jballoon.impl;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;

import net.eckenfels.jballoon.BalloonHash.BalloonParams;


/** Testing the AES-CTR pseudo random bitstream generator. */
class BitStreamTest
{
	@Test
	void testRand_uint64() throws NoSuchAlgorithmException
	{
		BalloonParams param = new BalloonParams(128, 3, 2);
		BitStream bs = BitStream.init(new byte[4], new byte[28], param);
		assertNotNull(bs);

		long l1 = bs.rand_uint64();
		long l2 = bs.rand_uint64();

		System.out.println("Rand: " + Long.toUnsignedString(l1, 16) + "," + Long.toUnsignedString(l2, 16));

		assertEquals(0x6e520471d670cc29L, l1); // TODO - comapre with reference
		assertEquals(0xe57a9a44796fe5bfL, l2); // TODO - compare with reference
	}

	@Test
	void testInit() throws NoSuchAlgorithmException
	{
		BitStream bs = BitStream.init(new byte[4], new byte[28], new BalloonParams());
		assertNotNull(bs);
	}
}
