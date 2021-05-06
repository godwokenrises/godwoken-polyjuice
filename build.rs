pub use blake2b_rs::{Blake2b, Blake2bBuilder};
use includedir_codegen::Compression;

use std::{
    env,
    fs::File,
    io::{BufWriter, Read, Write},
    path::Path,
};

const PATH_PREFIX: &str = "build/";
const BUF_SIZE: usize = 8 * 1024;
const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

const BINARIES: &[(&str, &str)] = &[
    (
        "generator",
        "a947d7256e014ee7211ec7ad645c3961dadbc33c6b21f63ab0178746e33fd02c",
    ),
    (
        "validator",
        "e3f1e83879a69cfe5a2617585fd066b91b573f5834ac40797ee5f781643cd9be",
    ),
    (
        "generator_log",
        "cdef27fa950fd088b9011289914a6913ff0fd4205877a5995a9d9464664626b2",
    ),
    (
        "validator_log",
        "a5e9fc8999d7ba82aaa09faf311f3f8993daee415deff36fe8d366fad0fde900",
    ),
];

fn main() {
    let mut bundled = includedir_codegen::start("BUNDLED_CELL");

    let out_path = Path::new(&env::var("OUT_DIR").unwrap()).join("code_hashes.rs");
    let mut out_file = BufWriter::new(File::create(&out_path).expect("create code_hashes.rs"));

    let mut errors = Vec::new();

    for (name, expected_hash) in BINARIES {
        let path = format!("{}{}", PATH_PREFIX, name);

        let mut buf = [0u8; BUF_SIZE];
        bundled
            .add_file(&path, Compression::Gzip)
            .expect("add files to resource bundle");

        // build hash
        let mut blake2b = new_blake2b();
        let mut fd = File::open(&path).expect("open file");
        loop {
            let read_bytes = fd.read(&mut buf).expect("read file");
            if read_bytes > 0 {
                blake2b.update(&buf[..read_bytes]);
            } else {
                break;
            }
        }

        let mut hash = [0u8; 32];
        blake2b.finalize(&mut hash);

        let actual_hash = faster_hex::hex_string(&hash).unwrap();
        if expected_hash != &actual_hash {
            errors.push((name, expected_hash, actual_hash));
            continue;
        }

        write!(
            &mut out_file,
            "pub const {}: [u8; 32] = {:?};\n",
            format!("CODE_HASH_{}", name.to_uppercase()),
            hash
        )
        .expect("write to code_hashes.rs");
    }

    if !errors.is_empty() {
        for (name, expected, actual) in errors.into_iter() {
            eprintln!("{}: expect {}, actual {}", name, expected, actual);
        }
        panic!("not all hashes are right");
    }

    bundled.build("bundled.rs").expect("build resource bundle");
}

pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}
