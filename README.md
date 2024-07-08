# SP1-friendly EigenDA commitment calculations

Provides `eigenda_kzg::commit()` to compute the same commitment that
EigenDA would compute efficiently in sp1. Note that the payload is
automatically padded as per the [blob serialization
requirements](https://docs.eigenlayer.xyz/eigenda/integrations-guides/dispersal/api-documentation/blob-serialization-requirements).

## Developing

To run tests and generate the precomputed G1 points, you first need to
download the points from [EigenDA's operator
setup](https://github.com/Layr-Labs/eigenda-operator-setup) into the
`points` directory. You should have two files, `points/g1.point` and
`points/g2.point.powerOf2`.

Tests are run from `tests/script`:

```
$ cd tests/script
$ cargo test
```

Be warned though, they are computationally quite expensive. You may want
to run them on a beefier machine. The number of threads can be
controlled by setting the environment variable `RAYON_NUM_THREADS`. You
may also want to adjust `SHARD_SIZE` and `SHARD_BATCH_SIZE` to limit
msemory ussage. See the [SP1
book](https://docs.succinct.xyz/generating-proofs/advanced.html).

```
$ RAYON_NUM_THREADS=4 SHARD_BATCH_SIZE=1 SHARD_SIZE=2097152 RUSTFLAGS='-C target-cpu=native' cargo test
```
