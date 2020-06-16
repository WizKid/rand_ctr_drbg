extern crate rand_ctr_drbg;

use rand_ctr_drbg::CtrDrbg;
use aes::block_cipher::generic_array::{GenericArray, ArrayLength};
use aes::{Aes128, Aes192, Aes256};
use std::fs::File;
use ron::de::from_reader;
use serde::Deserialize;
use aes::block_cipher::generic_array::typenum::{U32, U40, U48, U64};
use hex;
use rand::prelude::*;

#[derive(Debug, Deserialize)]
struct TestCase {
    pub derivation: bool,
    pub entropy_input: String,
    pub personalization_string: String,
    pub additional_input1: String,
    pub additional_input2: String,
    pub returned_bits: String,
}

fn hex_to_generic_array<T: ArrayLength<u8>>(input: &String) -> GenericArray<u8, T> {
    if input.len() == 0 {
        return GenericArray::<u8, T>::default();
    }
    GenericArray::<u8, T>::clone_from_slice(&hex::decode(input).unwrap()[..])
}

#[test]
fn nist_test_aes128() {
    let input_path = format!("{}/tests/data/aes128.ron", env!("CARGO_MANIFEST_DIR"));
    let f = File::open(&input_path).expect("Failed opening file");
    let test_cases: Vec<TestCase> = from_reader(f).expect("Failed to load config");

    for test_case in test_cases {
        let entropy_input = hex_to_generic_array::<U32>(&test_case.entropy_input);
        let pers = hex_to_generic_array::<U32>(&test_case.personalization_string);
        let expected = hex_to_generic_array::<U64>(&test_case.returned_bits);

        let mut ctr_drbg = CtrDrbg::<Aes128>::new(&entropy_input, &pers);

        let mut buffer: Vec<u8> = vec![0; 64];
        if test_case.additional_input1.len() > 0 {
            let add = hex_to_generic_array::<U32>(&test_case.additional_input1);
            ctr_drbg.fill_bytes_with_additional(&mut buffer, &add);
        } else {
            ctr_drbg.fill_bytes(&mut buffer);
        }

        let mut buffer: Vec<u8> = vec![0; 64];
        if test_case.additional_input2.len() > 0 {
            let add = hex_to_generic_array::<U32>(&test_case.additional_input2);
            
            ctr_drbg.fill_bytes_with_additional(&mut buffer, &add);
        } else {
            ctr_drbg.fill_bytes(&mut buffer);
        }

        assert_eq!(buffer[..], expected[..]);
    }
}

#[test]
fn nist_test_aes192() {
    let input_path = format!("{}/tests/data/aes192.ron", env!("CARGO_MANIFEST_DIR"));
    let f = File::open(&input_path).expect("Failed opening file");
    let test_cases: Vec<TestCase> = from_reader(f).expect("Failed to load config");

    for test_case in test_cases {
        let entropy_input = hex_to_generic_array::<U40>(&test_case.entropy_input);
        let pers = hex_to_generic_array::<U40>(&test_case.personalization_string);
        let expected = hex_to_generic_array::<U64>(&test_case.returned_bits);

        let mut ctr_drbg = CtrDrbg::<Aes192>::new(&entropy_input, &pers);

        let mut buffer: Vec<u8> = vec![0; 64];
        if test_case.additional_input1.len() > 0 {
            let add = hex_to_generic_array::<U40>(&test_case.additional_input1);
            ctr_drbg.fill_bytes_with_additional(&mut buffer, &add);
        } else {
            ctr_drbg.fill_bytes(&mut buffer);
        }

        let mut buffer: Vec<u8> = vec![0; 64];
        if test_case.additional_input2.len() > 0 {
            let add = hex_to_generic_array::<U40>(&test_case.additional_input2);
            
            ctr_drbg.fill_bytes_with_additional(&mut buffer, &add);
        } else {
            ctr_drbg.fill_bytes(&mut buffer);
        }

        assert_eq!(buffer[..], expected[..]);
    }
}

#[test]
fn nist_test_aes256() {
    let input_path = format!("{}/tests/data/aes256.ron", env!("CARGO_MANIFEST_DIR"));
    let f = File::open(&input_path).expect("Failed opening file");
    let test_cases: Vec<TestCase> = from_reader(f).expect("Failed to load config");

    for test_case in test_cases {
        let entropy_input = hex_to_generic_array::<U48>(&test_case.entropy_input);
        let pers = hex_to_generic_array::<U48>(&test_case.personalization_string);
        let expected = hex_to_generic_array::<U64>(&test_case.returned_bits);

        let mut ctr_drbg = CtrDrbg::<Aes256>::new(&entropy_input, &pers);

        let mut buffer: Vec<u8> = vec![0; 64];
        if test_case.additional_input1.len() > 0 {
            let add = hex_to_generic_array::<U48>(&test_case.additional_input1);
            ctr_drbg.fill_bytes_with_additional(&mut buffer, &add);
        } else {
            ctr_drbg.fill_bytes(&mut buffer);
        }

        let mut buffer: Vec<u8> = vec![0; 64];
        if test_case.additional_input2.len() > 0 {
            let add = hex_to_generic_array::<U48>(&test_case.additional_input2);
            
            ctr_drbg.fill_bytes_with_additional(&mut buffer, &add);
        } else {
            ctr_drbg.fill_bytes(&mut buffer);
        }

        assert_eq!(buffer[..], expected[..]);
    }
}