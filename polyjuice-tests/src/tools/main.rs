use std::{fs, path::PathBuf};

use ckb_vm::Bytes;
use clap::{arg, command, Command};
use gw_types::{packed::RawL2Transaction, prelude::*};

use polyjuice_tests::{ctx::CREATOR_ACCOUNT_ID, helper::PolyjuiceArgsBuilder};

fn main() {
    let matches = command!()
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("convert-bin")
                .about("Convert contract bins to bytes and write to files under a given directory.")
                .args(&[
                    arg!(-i --input <IN> "A dir to read bins from."),
                    arg!(-o --output <OUT> "A dir to write binaries."),
                    arg!(--overwrite "Overwrite existing files."),
                ]),
        )
        .subcommand(
            Command::new("convert-deploy-tx")
                .about("Convert contract bins to bytes of deploy tx and write to files under a given directory.")
                .args(&[
                    arg!(-i --input <IN> "A dir to read bins from."),
                    arg!(-o --output <OUT> "A dir to write binaries."),
                    arg!(--overwrite "Overwrite existing files."),
                ]),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("convert-bin", sub_matches)) => {
            println!("args: {:?}", sub_matches);
            let input = sub_matches
                .get_one::<String>("input")
                .expect("Need an input dir");
            let output = sub_matches
                .get_one::<String>("output")
                .expect("Need an output directory");
            let overwrite = sub_matches.get_one::<String>("overwrite").is_some();
            convert_bins(input, output, overwrite).expect("convert bins")
        }
        Some(("convert-deploy-tx", sub_matches)) => {
            println!("args: {:?}", sub_matches);
            let input = sub_matches
                .get_one::<String>("input")
                .expect("Need an input dir");
            let output = sub_matches
                .get_one::<String>("output")
                .expect("Need an output directory");
            let overwrite = sub_matches.get_one::<String>("overwrite").is_some();
            conv_deploy_tx(input, output, overwrite).expect("convert bins")
        }
        _ => unreachable!("Exhausted list of subcommands and subcommand_required prevents `None`"),
    }
}

/**
 * Convert contract bin files to bytes files. So those files can be used in fuzz as seeds.
 */
fn convert_bins(input_dir: &str, output_dir: &str, overwrite: bool) -> anyhow::Result<()> {
    fs::create_dir_all(output_dir)?;
    if let Ok(input_dir) = fs::read_dir(input_dir) {
        for file in input_dir.into_iter().flatten() {
            if let Some(ext) = file.path().extension() {
                if ext == "bin" {
                    println!("read file: {:?}", file.path());
                    let content = fs::read_to_string(file.path())?;
                    let bytes = match hex::decode(content) {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            println!("decode file: {:?}", err);
                            continue;
                        }
                    };
                    let mut path: PathBuf = PathBuf::from(output_dir);
                    path.push(file.file_name());
                    if path.exists() && !overwrite {
                        continue;
                    }
                    fs::write(path, bytes)?;
                }
            }
        }
    }
    Ok(())
}

/**
 * Convert contract bin files to bytes files of deploy transactions.
 */
fn conv_deploy_tx(input_dir: &str, output_dir: &str, overwrite: bool) -> anyhow::Result<()> {
    let gas_limit = 500000;
    let gas_price = 1;
    let value = 0;

    fs::create_dir_all(output_dir)?;
    if let Ok(input_dir) = fs::read_dir(input_dir) {
        for file in input_dir.into_iter().flatten() {
            if let Some(ext) = file.path().extension() {
                if ext == "bin" {
                    println!("read file: {:?}", file.path());
                    let content = fs::read_to_string(file.path())?;
                    let bytes = match hex::decode(content) {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            println!("decode file: {:?}", err);
                            continue;
                        }
                    };
                    let args = PolyjuiceArgsBuilder::default()
                        .do_create(true)
                        .gas_limit(gas_limit)
                        .gas_price(gas_price)
                        .value(value)
                        .input(&bytes)
                        .build();
                    let raw_tx = RawL2Transaction::new_builder()
                        .from_id(4u32.pack()) //TODO REMOVE HARDCODE
                        .to_id(CREATOR_ACCOUNT_ID.pack())
                        .args(Bytes::from(args).pack())
                        .build();
                    let mut path: PathBuf = PathBuf::from(output_dir);
                    path.push(file.file_name());
                    if path.exists() && !overwrite {
                        continue;
                    }
                    fs::write(path, raw_tx.as_slice())?;
                }
            }
        }
    }
    Ok(())
}
