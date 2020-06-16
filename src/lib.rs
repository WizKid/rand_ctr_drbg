use aes::block_cipher::{BlockCipher, NewBlockCipher, Key};
use aes::block_cipher::generic_array::{
    typenum::{U16, Sum, Unsigned},
    GenericArray, ArrayLength
};
use aes::{Aes128, Aes192, Aes256};
use rand_core::{RngCore, impls, Error};

pub trait CtrDrbgTrait {
    type EntropySize: ArrayLength<u8>;
}

impl CtrDrbgTrait for Aes128 {
    type EntropySize = Sum<<Self as NewBlockCipher>::KeySize, U16>;
}

impl CtrDrbgTrait for Aes192 {
    type EntropySize = Sum<<Self as NewBlockCipher>::KeySize, U16>;
}

impl CtrDrbgTrait for Aes256 {
    type EntropySize = Sum<<Self as NewBlockCipher>::KeySize, U16>;
}

type EntropySize<B> = <B as CtrDrbgTrait>::EntropySize;

// This doesn't work so that is why the CtrDrbgTrait is needed. Why the indirection solves it I have no idea
// Maybe something to do with in NewBlockCipher KeySize is ArrayLength but in the 3 specific Aes classes they are U??.
// type EntropySize<B> = Sum<<B as NewBlockCipher>::KeySize, U16>;

type Entropy<B> = GenericArray<u8, EntropySize<B>>;
type KeySize<B> = <B as NewBlockCipher>::KeySize;
type BlockSize = U16;
type Block = GenericArray<u8, BlockSize>;

pub struct CtrDrbg<B> where B: BlockCipher<BlockSize = U16> + NewBlockCipher + CtrDrbgTrait, B::ParBlocks: ArrayLength<Block> {
    ctx: B,
    ctr: Block,
}

impl<B> CtrDrbg<B> where B: BlockCipher<BlockSize = U16> + NewBlockCipher + CtrDrbgTrait, B::ParBlocks: ArrayLength<Block> {

    pub fn new(entropy: &Entropy<B>, pers: &Entropy<B>) -> CtrDrbg<B> {
        let key = Key::<B>::default();
        let ctr = Block::default();
        let mut s = CtrDrbg { ctx: B::new(&key), ctr: ctr };
        let mut seed = entropy.clone();
        for i in 0..pers.len() {
            seed[i] ^= pers[i];
        }
        s.update(Some(&seed));
        s
    }

    fn next_block(&mut self, dst: &mut GenericArray<u8, U16>) {
        for i in (0..16).rev() {
            self.ctr[i] = self.ctr[i].wrapping_add(1);
            if self.ctr[i] != 0x00 {
                break
            }
        }

        dst.copy_from_slice(self.ctr.as_slice());
        self.ctx.encrypt_block(dst);
    }

    fn next(&mut self, dst: &mut [u8]) {
        let len = dst.len();
        let mut i = 0;
        while i + BlockSize::to_usize() < len {
            self.next_block(Block::from_mut_slice(&mut dst[i..i+BlockSize::to_usize()]));
            i += BlockSize::to_usize();
        }
        if i < len {
            let mut tmp = Block::default();
            self.next_block(&mut tmp);
            dst[i..len].copy_from_slice(&tmp[0..len - i]);
        }
    }

    fn update(&mut self, add: Option<&Entropy<B>>) {
        let mut slab = Entropy::<B>::default();
        self.next(&mut slab);

        if let Some(seed) = add {
            for i in 0..seed.len() {
                slab[i] ^= seed[i];
            }
        }

        let (key, ctr) = slab.split_at_mut(KeySize::<B>::to_usize());

        self.ctx = B::new(Key::<B>::from_slice(key));
        self.ctr = Block::clone_from_slice(ctr);
    }

    pub fn fill_bytes_with_additional(&mut self, dest: &mut [u8], add: &Entropy<B>) {
        self.fill_bytes_impl(dest, Some(add))
    }

    fn fill_bytes_impl(&mut self, dest: &mut [u8], add: Option<&Entropy<B>>) {
        if let Some(_) = add {
            self.update(add);
        }

        self.next(dest);

        self.update(add);
    }
}

impl<B> RngCore for CtrDrbg<B> where B: BlockCipher<BlockSize = U16> + NewBlockCipher + CtrDrbgTrait, B::ParBlocks: ArrayLength<Block> {
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
