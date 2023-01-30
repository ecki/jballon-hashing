/* jballoon-hashing
 *
 * Copyright 2023 by Bernd Eckenfels. Germany.
 *
 * Granted under Apache License 2.0.
 */
package net.eckenfels.jballoon.impl;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.eckenfels.jballoon.BalloonHash.BalloonParams;

/**
 * Pseudo Random bit stream based on AES128-CTR with SHA-256
 * for seeding the key.
 */
// TODO cleanup key
class BitStream
{
	final static int BITSTREAM_BUFSIZE = 64; // TODO
	final static byte[] zeros = new byte[BITSTREAM_BUFSIZE];

	private final Cipher cipher;

	private BitStream(byte[] keyBytes)
	{
		try
		{
			SecretKey key = new SecretKeySpec(keyBytes, 0, 128 / 8, "AES");
			IvParameterSpec iv = new IvParameterSpec(new byte[16]);
			Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
			aes.init(Cipher.ENCRYPT_MODE, key, iv);

			this.cipher = aes;
		}
		catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ex)
		{
			throw new RuntimeException("TODO unexpected crypto exception: " + ex, ex);
		}
	}

	long rand_uint64()
	{
		try
		{
			byte[] tmp = new byte[8]; // todo keep
			// in CTR mode this wortks like a stream cipher
			int len = cipher.update(zeros, 0, 8, tmp);
			if (len != 8)
			{
				throw new RuntimeException("TODO: do the loop properly");
			}
			return (long)BalloonEngine.LONG.get(tmp, 0);
		}
		catch (ShortBufferException ex)
		{
			throw new RuntimeException("TODO unexpected ctypt exception: " + ex, ex);
		}
	}

	/** Seed the bitstream. */
	static BitStream init(byte[] firstBytes, byte[] salt, BalloonParams params) throws NoSuchAlgorithmException
	{
		MessageDigest hash = MessageDigest.getInstance("SHA-256");

		// Salt is modified with threadId
		hash.update(firstBytes); // todo: needed?
		hash.update(salt, 4, salt.length - 4);

		// parameters
		byte[] tmp = new byte[4];
		BalloonEngine.INT.set(tmp, 0, params.getSpaceCost());
		hash.update(tmp);

		BalloonEngine.INT.set(tmp, 0, params.getTimeCost());
		hash.update(tmp);

		BalloonEngine.INT.set(tmp, 0, params.getParallelity());
		byte[] key = hash.digest(tmp);

		return new BitStream(key);
	}
}
