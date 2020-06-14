extern crate ctr_drbg;

use ctr_drbg::CtrDrbg;
use aes::block_cipher::generic_array::GenericArray;
use aes::block_cipher::generic_array::typenum::U32;
use rand::prelude::*;

#[test]
fn test() {
    let entropy_input = GenericArray::<u8, U32>::default();
    let pers = GenericArray::<u8, U32>::default();

    let mut ctr_drbg = CtrDrbg::new(&entropy_input, &pers);

    assert_eq!(ctr_drbg.gen::<i32>(), -752546092);
    assert_eq!(ctr_drbg.gen::<i32>(), -1324191812);
    assert_eq!(ctr_drbg.gen::<bool>(), false);
    assert_eq!(ctr_drbg.gen::<bool>(), true);
}