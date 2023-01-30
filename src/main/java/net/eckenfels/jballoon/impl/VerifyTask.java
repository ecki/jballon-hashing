/* jballoon-hashing
 *
 * Copyright 2023 by Bernd Eckenfels. Germany.
 *
 * Granted under Apache License 2.0.
 */
package net.eckenfels.jballoon.impl;


import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RecursiveTask;

import net.eckenfels.jballoon.BalloonHash.BalloonParams;
import net.eckenfels.jballoon.BalloonHash.BalloonResult;
import net.eckenfels.jballoon.impl.BalloonEngine.BalloonWorker;


/**
 * Auxiliar ForkJoin task to kick off password hash verification.
 * <p>
 * Delegates back to {@link BalloonEngine}.
 */
public class VerifyTask extends RecursiveTask<Boolean>
{
	private static final long serialVersionUID = 3687014897260776562L;

	private final byte[] password;
	private final BalloonResult result;
	private final BalloonEngine engine;

	public VerifyTask(byte[] password, BalloonResult result, BalloonEngine engine)
	{
		this.password = Objects.requireNonNull(password, "VerifyTask(password)");
		this.result = Objects.requireNonNull(result, "VerifyTask(result)");
		this.engine = Objects.requireNonNull(engine, "VerifyTask(engine)");
	}

	// TODO merge with create task
	@Override
	protected Boolean compute()
	{
		// initialize random salt
		byte[] salt = result.getSalt();
		// TODO: test

		List<BalloonWorker> workers = new ArrayList<>(result.getParamParallelity());
		for(int i = 0; i < result.getParamParallelity(); i++)
		{
			workers.add(new BalloonWorker(i, engine, result.getParams(), password, salt));
		}

		invokeAll(workers);

		byte[] out = new byte[BalloonParams.BLOCK_SIZE]; // use a fresh one
		for(BalloonWorker w : workers)
		{
			try
			{
				byte[] result = w.get();
				BalloonEngine.xor(out, result);
			}
			catch (InterruptedException | ExecutionException e)
			{
				throw new RuntimeException("For worker w= " + w + " an unexpected exception=" + e, e);
			}
		}

		return MessageDigest.isEqual(out, result.getVerifier());
	}
}
