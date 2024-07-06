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

Tests are run from `tests/scripts`:

```
$ cd tests/scripts
$ cargo test
```

Be warned though, they are computationally quite expensive. You may
want to run them on a beefier machine.
