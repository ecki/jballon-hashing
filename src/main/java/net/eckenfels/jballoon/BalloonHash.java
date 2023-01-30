/* jballoon-hashing
 *
 * Copyright 2023 by Bernd Eckenfels. Germany.
 *
 * Granted under Apache License 2.0.
 */
package net.eckenfels.jballoon;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.ForkJoinPool;

import src.main.java.net.eckenfels.jballoon.impl.BalloonEngine;

/**
 * PublicAPI class for the jBalloon password hashing library.
 * <p>
 * You need to keep instance of this around when you want to use multiple
 * invocations. If setting an external ForkJoinPool you need to shut this
 * pool down yourself.
 *
 * @author Bernd Eckenfels
 * @see #verify(byte[], CharSequence)
 * @see #create(byte[])
 * @see #BalloonHash(ForkJoinPool)
 */
public final class BalloonHash
{
	private final BalloonEngine balloonEngine;

	/** Immutable and reuse able password hashing parameters. */
	public static final class BalloonParams
	{
		public static final int SALT_LEN = 32;
		public static final int BLOCK_SIZE = 256 / 8; // TODO

		private final int spaceCost;
		private final int timeCost;
		private final int parallelity;

		/**
		 * Use default params.
		 * <p>
		 * This will specify t=1, s=1024(1M), p=1 TODO.
		 * <p>
		 * Default parameters are used by {@link BalloonHash#hash(byte[])}.
		 *
		 * @see #BalloonHash(int, int, int)
		 */
		public BalloonParams()
		{
			this(1024, 1, 1); // TODO
		}

		/**
		 * Creates new parameter object with specified parameters.
		 *
		 * @param s space cost in kilobytes (rounded up to even blocks)
		 * @oaram t time cost in number of rounds
		 * @param p parallelity factor
		 * TODO: hash, rng
		 *
		 * @see BalliinHash#createHash
		 */
		public BalloonParams(int s, int t, int p)
		{
			spaceCost = s;
			timeCost = t;
			parallelity = p;
		}

		/** Get a initilaized salt block. */
		public byte[] createRandomSalt()
		{
			byte[] salt = new byte[SALT_LEN];
			try
			{
				// TODO:instance and config
				SecureRandom.getInstanceStrong().nextBytes(salt);
			}
			catch (NoSuchAlgorithmException e)
			{
				// TODO: error handling
				throw new RuntimeException("Cannot create random salt. cause=" + e, e);
			}
			return salt;
		}

		/** Configured space cost (in kiB) */
		public int getSpaceCost()
		{
			return spaceCost;
		}

		/** Configured compute cost in function iterations. */
		public int getTimeCost()
		{
			return timeCost;
		}

		/** Configured number of parallel instances executed in tasks. */
		public int getParallelity()
		{
			return parallelity;
		}
	}

	/** Holder for hash result, includes parsing/serializing. */
	public static final class BalloonResult
	{
		private final byte[] salt;
		private final byte[] verifier;

		private final int version;
		private final int spaceCost;
		private final int timeCost;
		private final int parallelity;

		public BalloonResult(byte[] salt, byte[] verifier, BalloonParams params)
		{
			Objects.requireNonNull(salt, "BalloonResult(salt) is required.");
			Objects.requireNonNull(verifier, "BalloonResult(verifier) is required.");

			// can only handle one version at the moment
			this.version = 1;

			this.salt = Arrays.copyOf(salt,  salt.length);
			this.verifier = Arrays.copyOf(verifier, verifier.length);

			this.spaceCost = params.getSpaceCost();
            this.timeCost = params.getTimeCost();
			this.parallelity = params.getParallelity();
		}

		public static BalloonResult decode(CharSequence encoded)
		{
			String encodedString = encoded.toString(); // todo unfortunate
			String[] split = encodedString.split("\\$");

			if (split.length != 6 || !split[0].isBlank() || !"balloon".equals(split[1]) || !"v=1".equals(split[2]))
			{
				throw new IllegalArgumentException("len " + split.length); // TODO
			}
			byte[] salt = b64d(split[4]);
			byte[] verifier = b64d(split[5]);
			int space = -1;
			int time = -1;
			int parallel = -1;
			split = split[3].split(",");
			for (String s : split)
			{
				if (s.startsWith("s="))
					space = extract(s);
				else if (s.startsWith("t="))
					time = extract(s);
				else if (s.startsWith("p"))
					parallel = extract(s);
				else
					System.out.println("Ignofing " + s);
			}
			//if (space == -1 || time == -1 || parallel == -1)

			BalloonParams params = new BalloonParams(space, time, parallel);
			return new BalloonResult(salt, verifier, params);
		}

		private static int extract(String s)
		{
			String[] split = s.split("=");
			if (split.length != 2)
			{
				throw new RuntimeException("TODO =");
			}
			return Integer.parseUnsignedInt(split[1]);
		}

		public int getVersion()
		{
			return version;
		}

		public int getParamSpace()
		{
			return spaceCost;
		}

		public int getParamTime()
		{
			return timeCost;
		}

		public int getParamParallelity()
		{
			return parallelity;
		}


		public BalloonParams getParams()
		{
			return new BalloonParams(spaceCost, timeCost, parallelity);
		}

		public byte[] getSalt()
		{
			return Arrays.copyOf(salt, salt.length);
		}

		public byte[] getVerifier()
		{
			return Arrays.copyOf(verifier, verifier.length);
		}

		// tODO: move?
		private static String b64e(byte[] bytes) {
			return Base64.getUrlEncoder().encodeToString(bytes).replaceAll("=", "");
		}

		// tODO: move?
		private static byte[] b64d(String encoded) {
			return Base64.getUrlDecoder().decode(encoded);
		}


		public String getEncoded()
		{
			return "$balloon$v=" + version + "$s=" + spaceCost + ",t=" + timeCost + ",p=" + parallelity + "$" + b64e(salt) + "$" + b64e(verifier);
		}

		@Override
		public String toString()
		{
			return "BalloonHash[encoded=" + getEncoded() + "]";
		}
	}

	/**
	 * Create new BalloonHash engine, using the common pool.
	 *
	 *  @see BalloonHash#BalloonHash(ForkJoinPool)
	 */
	public BalloonHash()
	{
		balloonEngine = new BalloonEngine(ForkJoinPool.commonPool());
	}

	public BalloonHash(ForkJoinPool poolArg)
	{
		balloonEngine = new BalloonEngine(Objects.requireNonNull(poolArg, "BallloonHash(pool) required."));
	}

	/**
	 * Create new BalloonHash instance with default options.
	 *
	 * @param password plaintext secret whichis to be encrypted.
	 *   Uses byte[] so you are free to chose aproperiate encoding,
	 *   UTF-8 recommended.
	 * @return the calculated hash as a result obejct, never null.
	 */
	public BalloonResult create(byte[] password)
	{
		BalloonParams param = new BalloonParams();
		return balloonEngine.hash(password, param);
	}

	/**
	 * Create new BalloonHash instance with default options.
	 *
	 * @param password plaintext secret whichis to be encrypted.
	 *   Uses byte[] so you are free to chose aproperiate encoding,
	 *   UTF-8 recommended.
	 * @return the calculated hash as a result obejct, never null.
	 */
	public BalloonResult create(byte[] password, BalloonParams param)
	{
		// TODO: no defensive copy?
		return balloonEngine.hash(password, param);
	}

	public boolean verify(byte[] password, CharSequence verifier)
	{
		BalloonResult decoded = BalloonResult.decode(verifier); // immutable
		// TODO: no defensive copy?
		return balloonEngine.verify(password, decoded);
	}

	public boolean verify(byte[] password, BalloonResult decoded)
	{
		// TODO: no defensive copy for password?
		return balloonEngine.verify(password, decoded);
	}

	// TODO async variants
}
