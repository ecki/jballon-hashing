/* jballoon-hashing
 *
 * Copyright 2023 by Bernd Eckenfels. Germany.
 *
 * Granted under Apache License 2.0.
 */
package net.eckenfels.jballoon.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RecursiveTask;

import net.eckenfels.jballoon.BalloonHash.BalloonParams;
import net.eckenfels.jballoon.BalloonHash.BalloonResult;
import net.eckenfels.jballoon.impl.BalloonEngine.BalloonWorker;


/**
 * Auxiliar ForkJoin Task to kick off password hash creation.
 * <p>
 * Delegates back to {@link BalloonEngine}.
 */
public final class CreateTask extends RecursiveTask<BalloonResult>
{
	private static final long serialVersionUID = 3687014897260776562L;

	private final byte[] password;
	private final BalloonParams param;
	private final BalloonEngine engine;

	public CreateTask(byte[] password, BalloonParams param, BalloonEngine engine)
	{
		this.password = password;
		this.param = param;
		this.engine = engine;
	}

	@Override
	protected BalloonResult compute()
	{
		// initialize random salt
		byte[] salt = param.createRandomSalt();

		List<BalloonWorker> workers = new ArrayList<>(param.getParallelity());
		for(int i = 0; i < param.getParallelity(); i++)
		{
			workers.add(new BalloonWorker(i, engine, param, password, salt));
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

		return new BalloonResult(salt, out, param);
	}
}
