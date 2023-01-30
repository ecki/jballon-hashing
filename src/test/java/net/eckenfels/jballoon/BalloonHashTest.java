/* jballoon-hashing
 *
 * Copyright 2023 by Bernd Eckenfels. Germany.
 *
 * Granted under Apache License 2.0.
 */
package net.eckenfels.jballoon;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import net.eckenfels.jballoon.BalloonHash.BalloonParams;
import net.eckenfels.jballoon.BalloonHash.BalloonResult;


class BalloonHashTest
{
	BalloonHash fixture = new BalloonHash();

	@Test
	void testDefaultConstructor()
	{
		assertNotNull(fixture);
	}

	@Test @Disabled // TODO
	void testVerifyWithResult()
	{
		BalloonResult result = new BalloonResult(new byte[64], new byte[64], new BalloonParams());
		assertTrue(fixture.verify(new byte[0], result), "Smoke Testvector: " + result);
	}

	@Test @Disabled // TODO
	void testVerifyWithEncoded()
	{
		BalloonResult result =  BalloonResult.decode("$balloon$v=1$t=1,s=2,p=1$MAEwn2xsLYXzmaHWc9-mSBg8eHNtYJM4-uxNLk6fu3twTIhY4y1WmqqR9YlAV7GwKX1Mq1b792sDu8aO5zsjUA$fJ-hNtRBP6YXNjfog7aZjTLh1nX4jN3_ncvPMxgg9LgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
		assertTrue(fixture.verify(new byte[0], result), "Smoke Testvector: " + result);
	}

	@Test
	void testCreate()
	{
		BalloonParams param = new BalloonParams(1,2,3);
		BalloonResult result = fixture.create(new byte[5], param);
		assertEquals(1, result.getVersion());
		assertEquals(32, result.getSalt().length);
		assertEquals(32, result.getVerifier().length);
		String encoded = result.getEncoded();

		String prefix = "$balloon$v=1$s=1,t=2,p=3$";
		assertEquals(prefix, encoded.substring(0, prefix.length()));

		System.out.println("Encoded: " + result.getEncoded());
	}

	@Test
	void testRountrip()
	{
		final byte[] PW = new byte[5];
		BalloonParams params = new BalloonParams(128, 3, 1);
		BalloonResult result = fixture.create(PW, params);
		String encoded = result.getEncoded();

		// verify intermediate result is plausible
		assertEquals(32, result.getSalt().length);
		assertEquals(32, result.getVerifier().length);
		String prefix = "$balloon$v=1$s=128,t=3,p=1$";
		assertEquals(prefix, encoded.substring(0, prefix.length()));

		// now verify both methods of validating password work
		assertTrue(fixture.verify(PW, result), "raw verify");
		//assertTrue(fixture.verify(PW, encoded), "encoded verify");
	}

	@Test
	void testWrongRountrip()
	{
		// yes we can encode 0 bytes
		final byte[] PW1 = new byte[5];
		final byte[] PW2 = new byte[5]; PW2[1] = (int)'a';
		BalloonParams params = new BalloonParams(1, 3, 1);

		BalloonResult result = fixture.create(PW1, params);
		String encoded = result.getEncoded();

		// verify intermediate result is plausible
		assertEquals(32, result.getSalt().length);
		assertEquals(32, result.getVerifier().length);
		String prefix = "$balloon$v=1$s=128,t=3,p=1$";
		//assertEquals(prefix, encoded.substring(0, prefix.length()));

		// make sure both methods detect a different password
		assertFalse(fixture.verify(PW2, encoded), "encoded verify false positive");
		assertFalse(fixture.verify(PW2, result), "raw verify false positive");
	}

}
