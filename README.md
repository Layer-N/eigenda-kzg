# SP1-friendly KZG commitments on BN254

Provides `eigenda_kzg::commit()` to compute the same commitment that
EigenDA would compute efficiently in SP1. Note that the serialization
format used **diverges from [blob serialization
requirements](https://docs.eigenlayer.xyz/eigenda/integrations-guides/dispersal/api-documentation/blob-serialization-requirements).**.
Instead, we delimit the data with a sentinel at the end. This has the
advantage of supporting committing to the empty string and never having
zero commitments.

## Developing

To run tests and generate the precomputed G1 points, you first need to
download the points from [EigenDA's operator
setup](https://github.com/Layr-Labs/eigenda-operator-setup) into the
`points` directory. You should have two files, `points/g1.point` and
`points/g2.point.powerOf2`.

To run the tests for the non-zkvm implementation, `cargo test` is used
as usual. To test the zkvm variant, use `cargo test` in the
`tests/script` directory instead.
