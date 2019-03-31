use rust_dense_bitset::{DenseBitSet, DenseBitSetExtended};

type Block = DenseBitSet;
type BigBlock = DenseBitSetExtended;

pub fn do_idea() {
    let plaintext = vec![DenseBitSet::from_integer(123456), DenseBitSet::from_integer(333)];
    let key = DenseBitSetExtended::from_string(String::from("fa24aa94fa541a94fab45a94fa745ac4"), 16);
    let ciphertext = encrypt(&plaintext, &key);
    let decrypted = decrypt(&ciphertext, &key);
    println!("Plaintext = {:?}", plaintext);
    println!("Key = {:?}", key);
    println!("Ciphertext = {:?}", ciphertext);
    println!("Decrypted = {:?}", decrypted);
}

fn encrypt(plaintext: &Vec<Block>, key: &BigBlock) -> Vec<Block> {
    let keys = extract_keys_from(key.clone());
    plaintext.iter().map(|block| forward_block(block, &keys)).collect()
}

fn decrypt(ciphertext: &Vec<Block>, key: &BigBlock) -> Vec<Block> {
    let keys = decryption_keys_from(key.clone());
    ciphertext.iter().map(|block| forward_block(block, &keys)).collect()
}

fn forward_block(block: &Block, keys: &Vec<Block>) -> Block {
    const SIZE: usize = 16;
    let mut n1 = DenseBitSet::from_integer(block.clone().extract(0 * SIZE, SIZE));
    let mut n2 = DenseBitSet::from_integer(block.clone().extract(1 * SIZE, SIZE));
    let mut n3 = DenseBitSet::from_integer(block.clone().extract(2 * SIZE, SIZE));
    let mut n4 = DenseBitSet::from_integer(block.clone().extract(3 * SIZE, SIZE));
    let mut key = keys.iter();
    for _round in 0..8 {
        let l1_1 = mul(&n1, key.next().unwrap());
        let l1_2 = add(&n2, key.next().unwrap());
        let l1_3 = add(&n3, key.next().unwrap());
        let l1_4 = mul(&n4, key.next().unwrap());

        let l2_2 = xor(l1_1, l1_3);
        let l2_3 = xor(l1_2, l1_4);

        let l3_2 = mul(&l2_2, key.next().unwrap());
        let l3_3 = add(&l3_2, &l2_3);
        let l4_3 = mul(&l3_3, key.next().unwrap());
        let l4_2 = add(&l3_2, &l4_3);

        let l5_1 = xor(l1_1, l4_3);
        let l5_3 = xor(l1_3, l4_3);
        let l5_2 = xor(l1_2, l4_2);
        let l5_4 = xor(l1_4, l4_2);

        n1 = l5_1;
        n2 = l5_3;
        n3 = l5_2;
        n4 = l5_4;
    }
    n1 = mul(&n1, key.next().unwrap());
    let nn2 = add(&n3, key.next().unwrap());
    let nn3 = add(&n2, key.next().unwrap());
    n4 = mul(&n4, key.next().unwrap());
    n2 = nn2;
    n3 = nn3;

    ((n1 << (0 * SIZE)) |
     (n2 << (1 * SIZE)) |
     (n3 << (2 * SIZE)) |
     (n4 << (3 * SIZE)))
}

fn extract_keys_from(mut bigkey: BigBlock) -> Vec<Block> {
    const KEY_LENGTH: usize = 16;
    let mut keys = Vec::new();
    for index in 1..=52 {
        let i = (index - 1) % 8;
        let key = DenseBitSet::from_integer(bigkey.extract_u64(i * KEY_LENGTH, KEY_LENGTH));
        keys.push(key);

        if index % 8 == 0 { // rotate
            bigkey = bigkey.rotl(25);
        }
    }
    keys
}

fn decryption_keys_from(bigkey: BigBlock) -> Vec<Block> {
    let keys = extract_keys_from(bigkey);
    let mut decr = Vec::new();
    for index in 0..8 {
        let i = 4 + 6 * (8 - index - 1);
        for j in 2..6 {
            if j == 2 || j == 5 {
                decr.push(mul_inv(keys[i + j]));
            } else {
                if index == 0 {
                    decr.push(add_inv(keys[i + j]));
                } else {
                    if j == 3 {
                        decr.push(add_inv(keys[i + j + 1]));
                    } else if j == 4 {
                        decr.push(add_inv(keys[i + j - 1]));
                    }
                }
            }
        }
        for j in 0..2 { decr.push(keys[i + j]); }
    }
    for j in 0..4 {
        if j == 0 || j == 3 {
            decr.push(mul_inv(keys[j]));
        } else {
            decr.push(add_inv(keys[j]));
        }
    }
    decr
}

fn xor(block1: Block, block2: Block) -> Block {
    block1 ^ block2
}

fn add(block1: &Block, block2: &Block) -> Block {
    let result = (block1.to_integer() + block2.to_integer()) & 0xFFFF; // % 2^16
    DenseBitSet::from_integer(result)
}

fn mul(block1: &Block, block2: &Block) -> Block {
    let mut block1 = block1.to_integer();
    let mut block2 = block2.to_integer();
    if block1 == 0 { block1 = 0xFFFF + 1; }
    if block2 == 0 { block2 = 0xFFFF + 1; }
    let mut result = (block1 * block2) % (0xFFFF + 2);
    if result == 0xFFFF + 1 { result = 0; }
    DenseBitSet::from_integer(result)
}

fn add_inv(n: Block) -> Block {
    let n = n.to_integer();
    if n == 0 { return DenseBitSet::from_integer(0); }
    DenseBitSet::from_integer((0xFFFF + 1) - n)
}

fn mul_inv(n: Block) -> Block {
    let n = n.to_integer();
    if n == 0 { return DenseBitSet::from_integer(0); }
    for i in 1..(0xFFFF + 1) {
        if (i * n) % (0xFFFF + 2) == 1 {
            return DenseBitSet::from_integer(i);
        }
    }
    panic!("Could not find for {}", n);
}
