/* jballoon-hashing
 *
 * Copyright 2023 by Bernd Eckenfels. Germany.
 *
 * Granted under Apache License 2.0.
 */
package net.eckenfels.jballoon.impl;


import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;
import java.util.concurrent.RecursiveTask;

import net.eckenfels.jballoon.BalloonHash.BalloonParams;
import net.eckenfels.jballoon.BalloonHash.BalloonResult;


/** Implementation of the Balloon function. */
public final class BalloonEngine
{
	static final VarHandle INT = createVH(int[].class);
	static final VarHandle LONG = createVH(long[].class);

	private final ForkJoinPool pool;

	static final class HashState
	{
		long counter;
		ByteBuffer[] buffer;
		boolean hasMixed;
		BalloonParams opts;
		BitStream bitstream;
		MessageDigest hash;

		HashState() throws NoSuchAlgorithmException
		{
			 hash = MessageDigest.getInstance("SHA-256");
		}
	}

	static final class BalloonWorker extends RecursiveTask<byte[]>
	{
		private static final long serialVersionUID = 1233692053894624662L;

		private int threadIdx;
		private BalloonEngine engine;

		private BalloonParams param;
		private byte[] password;
		private byte[] salt;


		BalloonWorker(int threadIdx, BalloonEngine engine, BalloonParams param, byte[] password, byte[] salt)
		{
			this.threadIdx = threadIdx;
			this.engine = engine;
			this.param = param;
			this.password = password;
			this.salt = salt;
		}

		@Override
		protected byte[] compute()
		{
			byte[] password = this.password; this.password = null;
			byte[] salt = this.salt; this.salt = null;
			BalloonParams param = this.param; this.param = null;

			try
			{
				return engine.work(threadIdx, param, password, salt);
			}
			catch (GeneralSecurityException e)
			{
				completeExceptionally(e);
				return null; // TODO?!
			}
		}
	}


	public BalloonEngine(ForkJoinPool poolArg)
	{
		this.pool = Objects.requireNonNull(poolArg);
	}

	/**
	 * Create balloon hash of password.
	 * <p>
	 * This waits for the task to complete, see {@link #hashAsync(byte[], BalloonParams)}
	 * for a version with a {@link Future}.
	 *
	 * @param password password in raw bytes (normally UTF-8 or ASCII)
	 * @param param configuration of cost and parallelity
	 * @return the result object containing the salt and verifier
	 */
	public BalloonResult hash(byte[] password, BalloonParams param)
	{
		// all balloon function logic is done in own background task which then forks
		CreateTask task = new CreateTask(password, param, this);
		return pool.invoke(task);
	}

	/**
	 * Create balloon hash of password.
	 * <p>
	 * This does not wait for the task to complete, but returns a future.
	 * See {@link #hash(byte[], BalloonParams)} for a blocking version.
	 *
	 * @param password password in raw bytes (normally UTF-8 or ASCII)
	 * @param param configuration of cost and parallelity
	 * @return the result object containing the salt and verifier in a future.
	 */
	public Future<BalloonResult> hashAsync(byte[] password, BalloonParams param)
	{
		// all balloon function logic is done in own background task which then forks
		CreateTask task = new CreateTask(password, param, this);
		return pool.submit(task);
	}

	/**
	 * Verify password with balloon hash.
	 *
	 * @param password password in raw bytes (normally UTF-8 or ASCII)
	 * @param result result of previous hashing (potentially using
	 *   {@link BalloonResult#decode(CharSequence)} to parse string representation.
	 * @return true if password hashes to same verifier
	 */
	public boolean verify(byte[] password, BalloonResult result)
	{
		// result - parsing the encoded string is done in caller thread
		// all balloon function logic is done in own background task which then forks
		// we could use the CreateTask here, but VerifyTask dos also the verifier compare in background
		VerifyTask task = new VerifyTask(password, result, this);
		return pool.invoke(task);
	}

	/**
	 * Verify password with balloon hash.
	 * <p>
	 * This is the async version returning a {@link Future}, see {@link #verify(byte[], BalloonResult)}
	 * for the blocking variant.
	 *
	 * @param password password in raw bytes (normally UTF-8 or ASCII)
	 * @param result result of previous hashing (potentially using
	 *   {@link BalloonResult#decode(CharSequence)} to parse string representation.
	 * @return true if password hashes to same verifier
	 */
	public Future<Boolean> verifyAsync(byte[] password, BalloonResult result)
	{
		// parsing the encoded string is done in caller thread

		// we make sure everything including the parsing is with controlled parallelity (in the pool)
		VerifyTask task = new VerifyTask(password, result, this);
		return pool.submit(task);
	}

	/**
	 * Compress multiple blocks into one
	 * <p>
	 * See compress.c # compress
	 *
	 * Does NOT increase counter.
	 * @throws DigestException
	 */
	void compress(MessageDigest hash,long counter, ByteBuffer out, ByteBuffer... blocks) throws DigestException
	{
		byte[] tmp = new byte[8];
		LONG.set(tmp, 0, counter);
		hash.update(tmp);

		for(ByteBuffer block : blocks)
		{
			block.flip();
			hash.update(block);
		}

		// write directly to target buffer
		hash.digest(out.array(), 0, BalloonParams.BLOCK_SIZE);
		out.position(32);
	}

	/**
	 * Hash block zero into the rest of the buffer.
	 * @throws DigestException
	 */
	void expand(HashState state) throws DigestException
	{
		ByteBuffer[] blocks = state.buffer;
		for(int i=1; i < blocks.length; i++)
		{
			compress(state.hash, state.counter++, /*out*/blocks[i], blocks[i-1]);
		}
	}

	// see balloon_worker()
	byte[] work(int threadIdx, BalloonParams params, byte[] password, byte[] salt) throws GeneralSecurityException
	{
		HashState state = new HashState();

		hash_state_init_and_fill(state, salt, password, params, threadIdx);

		for(long i=0; i < params.getTimeCost(); i++)
		{
			hash_state_mix(state);
		}

		return hash_state_extract(state);
	}

	void hash_state_init_and_fill(HashState state, byte[] salt, byte[] password, BalloonParams params, int threadId) throws GeneralSecurityException
	{
		state.counter = 0L;
		state.hasMixed = false;
		state.opts = params;

		int nblocks = params.getSpaceCost() * 1024 / BalloonParams.BLOCK_SIZE; // todo: int
		if (nblocks % 2 == 1)
		{
			nblocks++;
		}

		ByteBuffer[] buffer = new ByteBuffer[nblocks];
		for(int i=0; i < buffer.length; i++)
		{
			buffer[i] = ByteBuffer.allocate(BalloonParams.BLOCK_SIZE);
		}
		state.buffer = buffer;

		// instead of copying salt to each thread we handle it in two blocks
		byte[] tmp = new byte[8];
		int firstint = ((int)INT.get(salt, 0)) + threadId;
		INT.set(tmp, 0, firstint);

		state.bitstream = BitStream.init(tmp, salt, params); // todo: seeded saltcorrect?

		// fill first block
		MessageDigest hash = state.hash;

		LONG.set(tmp, 0, state.counter);
		hash.update(tmp);

		// salt but the first 32bits are threadid
		INT.set(tmp, 0, firstint);
		hash.update(tmp, 0, 4);
		hash.update(salt, 4, salt.length - 4);

		hash.update(password);

		INT.set(tmp, 0, params.getSpaceCost());
		hash.update(tmp, 0, 4);

		INT.set(tmp, 0, params.getTimeCost());
		hash.update(tmp, 0, 4);

		INT.set(tmp, 0, params.getParallelity());
		hash.update(tmp,0 ,4);

		// write result into first block
		ByteBuffer out = state.buffer[0];
		hash.digest(out.array(), 0, BalloonParams.BLOCK_SIZE);
		out.position(32);

//for(int p=0; p < 16; p++)
//	System.out.printf("%02x ", state.buffer[0].get(p));
//System.out.println();

		// now expand to rest of blocks
		expand(state);
	}

	private void hash_state_mix(HashState state) throws DigestException
	{
//		const size_t n_blocks_to_hash = 3;
		final int DELTA = 3; // blocks to hash

//		const uint8_t *blocks[2+n_blocks_to_hash];
		ByteBuffer[] blocks = new ByteBuffer[2 + DELTA];

//      for (size_t i = 0; i < s->n_blocks; i++) {
		for(int i = 0; i < state.buffer.length; i++)
		{
//			uint8_t *cur_block = block_index (s, i);
//
//			// Hash in the previous block (or the last block if this is
//			// the first block of the buffer).
//			const uint8_t *prev_block = i ? cur_block - BLOCK_SIZE : block_last (s);
			int prev_idx = i > 0 ? i - 1 : state.buffer.length - 1;
//
//			blocks[0] = prev_block;
			blocks[0] = state.buffer[prev_idx];
//			blocks[1] = cur_block;
			blocks[1] = state.buffer[i];

//			// For each block, pick random neighbors
//			for (size_t n = 2; n < 2+n_blocks_to_hash; n++) {
			for(int n = 2; n < blocks.length; n++)
			{
//				// Get next neighbor
//				if ((error = bitstream_rand_uint64 (&s->bstream, &neighbor)))
//					return error;
//				blocks[n] = block_index (s, neighbor % s->n_blocks);
				long neighbor = state.bitstream.rand_uint64();
				int neighborIdx  = (int)Long.remainderUnsigned(neighbor, (long)state.buffer.length); //TODO safe cast
				blocks[n] = state.buffer[neighborIdx]; // TODO Bias?->upstream
			}

//			// Hash value of neighbors into temp buffer.
//			if ((error = compress (&s->counter, cur_block, blocks, 2+n_blocks_to_hash)))
//				return error;
			compress(state.hash, state.counter++, state.buffer[i], blocks);
		}
//		s->has_mixed = true;
		state.hasMixed = true;
//		return ERROR_NONE;
	}

	private byte[] hash_state_extract(HashState state)
	{
		if(!state.hasMixed)
		{
			throw new IllegalStateException("Cannot extract before mix.");
		}

		if (state.counter < 2)
		{
			throw new RuntimeException("todo: debug counter " + state.counter);
		}

		return state.buffer[state.buffer.length-1].array(); // todo copy?
	}


	/** xor content of out with second and store it back to out. */
    static void xor(byte[] out, byte[] second)
	{
		assert (out.length == second.length);

		for(int i = 0; i < out.length; i++)
		{
			out[i] ^= second[i];
		}
	}

	private static VarHandle createVH(Class<?> viewArrayClass)
	{
		return MethodHandles.byteArrayViewVarHandle(viewArrayClass, ByteOrder.LITTLE_ENDIAN);
	}

}
