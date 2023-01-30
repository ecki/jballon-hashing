# jballon-hashing

Java implementation of the balloon password hashing function.

WARNING: This is work in progress, it is not performance optimized, security reviewed or hardened, compatibility or functional tested.

GitHub Page: https://github.com/ecki/jballon-hashing

## License and Author

The code is Copyright 2023 Bernd Eckenfels, Germany. It is released under the Apache License 2.0.

## Compiling

You should be able to run `mvn verify` to build and test the code.

## Usage

The main entry is the class `net.eckenfels.jbaloon.BalloonHash`. It uses Java 8 features and requires a ForkJoinPool.

```java
   import net.eckenfels.jballoon.BalloonHash;

   BalloonHash balloon = new BalloonHash();
   BalloonResult verifier = balloon.hash("secret".getBytes(StandardCharset.UTF8);
   System.out.println("Your hash is: " + verifier.getEncoded());

   BalloonResult verifier = BallonResult.decode("$balloon$v=1$s=1,t=2,p=3$kl7_gjs1BX_Fy0ye5S5B-nz-MxxZc0P0SIKqnkhj4Wk$06UeQMy3uWRUnPz3CudHI-uw-fg6BR0JDGkjQLn5bVM");
   boolean result = balloon.verify("secret", verifier);
   System.out.println("Your password was correct: " + result);
```

## See Also

* C Reference Implementation https://github.com/henrycg/balloon
* Project Website: https://crypto.stanford.edu/balloon/
* Paper: https://eprint.iacr.org/2016/027 **Balloon Hashing: A Memory-Hard Function Providing Provable Protection Against Sequential Attacks**
*Dan Boneh*, *Henry Corrigan-Gibbs*, and *Stuart Schechter*
* Wikipedia: https://en.wikipedia.org/wiki/Balloon_hashing

## Other Implementations

* Go https://github.com/bytejedi/balloon
* Python https://github.com/nachonavarro/balloon-hashing
* Rust https://crates.io/crates/balloon-hash
