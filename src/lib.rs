use aes::block_cipher::generic_array::GenericArray;
use aes::block_cipher::{BlockCipher, NewBlockCipher};
use aes::block_cipher::generic_array::typenum::{U16, U32};
use aes::Aes128;
use rand_core::{RngCore, impls, Error};

pub struct CtrDrbg {
    ctx: Aes128,
    ctr: GenericArray<u8, U16>,
}

impl CtrDrbg {
    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 16;

    pub fn new(entropy: &GenericArray<u8, U32>, pers: &GenericArray<u8, U32>) -> CtrDrbg {
        let key = GenericArray::<u8, U16>::default();
        let mut s = CtrDrbg { ctx: Aes128::new(&key), ctr: key };
        let mut seed = entropy.clone();
        for i in 0..pers.len() {
            seed[i] ^= pers[i];
        }
        s.update(Some(&seed));
        s
    }

    fn next(&mut self, dst: &mut GenericArray<u8, U16>) {
        for i in (0..16).rev() {
            self.ctr[i] = self.ctr[i].wrapping_add(1);
            if self.ctr[i] != 0x00 {
                break
            }
        }

        dst.copy_from_slice(self.ctr.as_slice());
        self.ctx.encrypt_block(dst);
    }

    fn update(&mut self, add: Option<&GenericArray<u8, U32>>) {
        let mut slab = [0x0; CtrDrbg::KEY_SIZE + CtrDrbg::BLOCK_SIZE];

        let (a, b) = slab.split_at_mut(CtrDrbg::KEY_SIZE);

        self.next(GenericArray::<u8, U16>::from_mut_slice(a));
        self.next(GenericArray::<u8, U16>::from_mut_slice(b));

        if let Some(seed) = add {
            for i in 0..seed.len() {
                slab[i] ^= seed[i];
            }
        }

        let (a, b) = slab.split_at_mut(CtrDrbg::KEY_SIZE);

        self.ctx = Aes128::new(GenericArray::<u8, U16>::from_slice(a));
        self.ctr = GenericArray::<u8, U16>::clone_from_slice(b);
    }

    pub fn fill_bytes_with_additional(&mut self, dest: &mut [u8], add: &GenericArray<u8, U32>) {
        self.fill_bytes_impl(dest, Some(add))
    }

    fn fill_bytes_impl(&mut self, dest: &mut [u8], add: Option<&GenericArray<u8, U32>>) {
        if let Some(_) = add {
            self.update(add);
        }

        let len = dest.len();
        let mut i: usize = 0;
        while i + CtrDrbg::BLOCK_SIZE <= len {
            self.next(GenericArray::from_mut_slice(&mut dest[i..i + CtrDrbg::BLOCK_SIZE]));
            i += CtrDrbg::BLOCK_SIZE;
        }
        if i < dest.len() {
            let mut tmp = GenericArray::<u8, U16>::clone_from_slice(&[0; CtrDrbg::BLOCK_SIZE]);
            self.next(&mut tmp);
            dest[i..len].copy_from_slice(&tmp[0..len - i]);
        }
        self.update(add);
    }
}

impl RngCore for CtrDrbg {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill_bytes_impl(dest, None);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }

    fn next_u32(&mut self) -> u32 {
        return impls::next_u32_via_fill(self);
    }

    fn next_u64(&mut self) -> u64 {
        return impls::next_u64_via_fill(self);
    }
}
