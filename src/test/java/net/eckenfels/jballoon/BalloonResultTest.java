/* jballoon-hashing
 *
 * Copyright 2023 by Bernd Eckenfels. Germany.
 *
 * Granted under Apache License 2.0.
 */
package net.eckenfels.jballoon;


import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import net.eckenfels.jballoon.BalloonHash.BalloonParams;
import net.eckenfels.jballoon.BalloonHash.BalloonResult;


class BalloonResultTest
{
	@Test
	void testEncoded()
	{
		BalloonParams param = new BalloonParams(1,2,3);
		BalloonResult result = new BalloonHash.BalloonResult(new byte[1], new byte[1], param);

		assertEquals("$balloon$v=1$s=1,t=2,p=3$AA$AA", result.getEncoded()); // TODO verifiy
	}

	@Test
	void testDecodeValid()
	{
		//yes we are testing getters :)
		BalloonResult result = BalloonResult.decode("$balloon$v=1$t=0,s=0,p=1$AA==$AA==");
		assertEquals(1, result.getVersion());
		assertEquals(0, result.getParamSpace());
		assertEquals(0, result.getParamTime());
		assertEquals(1, result.getParamParallelity());
		assertEquals(1, result.getSalt().length);
		assertEquals(1, result.getVerifier().length);

		result = BalloonResult.decode("$balloon$v=1$t=2,s=3,p=4$AA$AA");
		assertEquals(1, result.getVersion());
		assertEquals(3, result.getParamSpace());
		assertEquals(2, result.getParamTime());
		assertEquals(4, result.getParamParallelity());
		assertEquals(1, result.getSalt().length);
		assertEquals(1, result.getVerifier().length);

		result = BalloonResult.decode("$balloon$v=1$t=5,s=6,p=7$AA$AA");
		assertEquals(1, result.getVersion());
		assertEquals(5, result.getParamTime());
		assertEquals(5, result.getParams().getTimeCost());
		assertEquals(6, result.getParamSpace());
		assertEquals(6, result.getParams().getSpaceCost());
		assertEquals(7, result.getParamParallelity());
		assertEquals(7, result.getParams().getParallelity());
		assertEquals(1, result.getSalt().length);
		assertEquals(1, result.getVerifier().length);

		// TODO: strict?
		result = BalloonResult.decode("$balloon$v=1$t=5,t=6,t=7$AA$AA");
		assertEquals(7, result.getParamTime());

		// reorder options
		result = BalloonResult.decode("$balloon$v=1$p=7,s=6,t=5$AA$AA");
		assertEquals(1, result.getVersion());
		assertEquals(6, result.getParamSpace());
		assertEquals(5, result.getParamTime());
		assertEquals(7, result.getParams().getParallelity());
		assertEquals(1, result.getSalt().length);
		assertEquals(1, result.getVerifier().length);
	}

	@Test @Disabled
	void testDecodeInvalid()
	{
	}


}
