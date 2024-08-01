const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
const SAMPLES_DIR: &str = "../../samples";

fn commit_native(payload: &[u8]) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    eigenda_kzg::commit(payload).map_err(Into::into)
}

fn commit_sp1(payload: &[u8]) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    sp1_sdk::utils::setup_logger();
    let mut stdin = sp1_sdk::SP1Stdin::new();
    stdin.write_slice(payload);
    let client = sp1_sdk::ProverClient::new();
    let (pub_vals, _report) = client.execute(ELF, stdin)?;
    Ok(pub_vals.as_slice().try_into().unwrap())
}

#[test]
fn samples() {
    for entry in std::fs::read_dir(SAMPLES_DIR).unwrap() {
        let path = entry.unwrap().path();

        if path.extension().unwrap() == "commit" {
            continue;
        }

        assert_eq!(path.extension().unwrap(), "data");
        let data = std::fs::read(&path).unwrap();
        let expect = std::fs::read(path.with_extension("commit")).unwrap();
        let expect = <[u8; 64]>::try_from(expect).unwrap();
        assert_eq!(commit_sp1(&data).unwrap(), expect);
    }
}

#[test]
fn empty() {
    assert_eq!(commit_sp1(&[]).unwrap(), commit_native(&[]).unwrap());
}

#[test]
fn too_large() {
    let xs = vec![1; eigenda_kzg::MAX_BLOB_SIZE + 1];
    assert!(commit_sp1(&xs).is_err());
    assert!(commit_native(&xs).is_err());
    let xs = vec![1; eigenda_kzg::MAX_BLOB_SIZE];
    assert_eq!(commit_sp1(&xs).unwrap(), commit_native(&xs).unwrap());
}
