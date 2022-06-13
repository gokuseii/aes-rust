use std::ops::Div;

static S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

static RS_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

static R_CON: [u8; 32] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
];

struct AES {
    round_keys: Vec<u8>,
    nr: u8,
}

impl AES {
    fn new(key: Vec<u8>) -> Self {
        let nk = key.len().div(4) as u8;
        let nr = match nk {
            4 => 10,
            6 => 12,
            8 => 14,
            _ => {
                panic!("Incorrect key lenght");
            }
        };
        AES {
            round_keys: Self::key_expansion(key, nk, nr),
            nr,
        }
    }

    fn shift_rows(block: &mut Vec<u8>) {
        let mut t: u8 = block[1];
        for i in 0..3 {
            block[i * 4 + 1] = block[(i + 1) * 4 + 1];
        }
        block[13] = t;

        t = block[2];
        block[2] = block[10];
        block[10] = t;
        t = block[6];
        block[6] = block[14];
        block[14] = t;

        t = block[3];
        block[3] = block[15];
        block[15] = block[11];
        block[11] = block[7];
        block[7] = t;
    }

    fn inv_shift_rows(block: &mut Vec<u8>) {
        let mut t: u8 = block[13];
        for i in 0..3 {
            block[(3 - i) * 4 + 1] = block[(3 - i - 1) * 4 + 1];
        }
        block[1] = t;

        t = block[2];
        block[2] = block[10];
        block[10] = t;
        t = block[6];
        block[6] = block[14];
        block[14] = t;

        t = block[3];
        for i in 0..3 {
            block[i * 4 + 3] = block[(i + 1) * 4 + 3];
        }
        block[15] = t;
    }

    fn xtime(x: u8) -> u8 {
        return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
    }

    fn mix_columns(block: &mut Vec<u8>) {
        for x in 0..4 {
            let mut t = block[x * 4];
            for i in 1..4 {
                t ^= block[x * 4 + i];
            }
            let tt = block[x * 4];
            for i in 0..3 {
                block[x * 4 + i] ^= t ^ Self::xtime(block[x * 4 + i] ^ block[x * 4 + i + 1]);
            }
            block[x * 4 + 3] ^= t ^ Self::xtime(block[x * 4 + 3] ^ tt);
        }
    }

    fn inv_mix_columns(block: &mut Vec<u8>) {
        for x in 0..4 {
            let t = Self::xtime(Self::xtime(block[x * 4] ^ block[x * 4 + 2]));
            let tt = Self::xtime(Self::xtime(block[x * 4 + 1] ^ block[x * 4 + 3]));
            for y in 0..4 {
                if y % 2 == 0 {
                    block[x * 4 + y] ^= t;
                } else {
                    block[x * 4 + y] ^= tt;
                }
            }
        }
        Self::mix_columns(block);
    }

    fn sub_bytes(block: &mut Vec<u8>) {
        for i in 0..4 {
            for j in 0..4 {
                block[i * 4 + j] = S_BOX[block[i * 4 + j] as usize];
            }
        }
    }

    fn inv_sub_bytes(block: &mut Vec<u8>) {
        for i in 0..4 {
            for j in 0..4 {
                block[i * 4 + j] = RS_BOX[block[i * 4 + j] as usize];
            }
        }
    }

    fn sub_word(t: &mut Vec<u8>) {
        for i in 0..4 {
            t[i] = S_BOX[t[i] as usize];
        }
    }

    fn key_expansion(key: Vec<u8>, nk: u8, nr: u8) -> Vec<u8> {
        let mut w: Vec<u8> = key.clone();

        for i in (nk as usize)..(4 * (nr + 1) as usize) {
            let mut temp = vec![
                w[4 * (i - 1)],
                w[4 * (i - 1) + 1],
                w[4 * (i - 1) + 2],
                w[4 * (i - 1) + 3],
            ];
            if i as u8 % nk == 0 {
                temp.rotate_left(1);
                Self::sub_word(&mut temp);
                temp[0] ^= R_CON[(i as u8).div(nk) as usize];
            } else if nk > 6 && (i as u8) % nk == 4 {
                Self::sub_word(&mut temp);
            }
            for j in 0..4 {
                w.push(w[(4 * (i as u8 - nk)) as usize + j] ^ temp[j]);
            }
        }
        w
    }

    fn add_round_key(&self, block: &mut Vec<u8>, round: usize) {
        for x in 0..4 as usize {
            for y in 0..4 as usize {
                block[x * 4 + y] ^= self.round_keys[(round * 16) + x * 4 + y];
            }
        }
    }

    fn into_blocks(&self, m_bytes: &Vec<u8>) -> Vec<Vec<u8>> {
        let mut blocks: Vec<Vec<u8>> = Vec::default();
        for i in (0..m_bytes.len()).step_by(16) {
            let mut block: Vec<u8> = Vec::default();
            for x in 0..4 {
                for y in 0..4 {
                    block.push(m_bytes[(x * 4 + y + i) as usize]);
                }
            }
            blocks.push(block);
        }
        blocks
    }

    fn pad(block: &mut Vec<u8>) {
        let pad_len: u8 = 16 - (block.len() % 16) as u8;
        for _ in 0..pad_len {
            block.push(pad_len);
        }
    }

    fn unpad(block: &mut Vec<u8>) {
        let pad_len = block.last().unwrap().clone() as usize;
        for i in 1..pad_len + 1 {
            block.remove(16 - i);
        }
    }

    fn encrypt_block(&self, block: &mut Vec<u8>) {
        self.add_round_key(block, 0);
        for round in 1..(self.nr as usize) + 1 {
            Self::sub_bytes(block);
            Self::shift_rows(block);
            if round < self.nr as usize {
                Self::mix_columns(block);
                self.add_round_key(block, round);
            }
        }
        self.add_round_key(block, self.nr as usize);
    }

    fn decrypt_block(&self, block: &mut Vec<u8>) {
        self.add_round_key(block, self.nr as usize);
        Self::inv_shift_rows(block);
        Self::inv_sub_bytes(block);
        for round in 1..(self.nr as usize) + 1 {
            let r = self.nr as usize - round;
            self.add_round_key(block, r);
            if r > 0 {
                Self::inv_mix_columns(block);
                Self::inv_shift_rows(block);
                Self::inv_sub_bytes(block);
            }
        }
    }

    fn cipher(&self, input: Vec<u8>) -> Vec<Vec<u8>> {
        let mut bytes = input;
        Self::pad(&mut bytes);
        let blocks = &mut self.into_blocks(&bytes);
        for block in blocks.into_iter() {
            self.encrypt_block(block);
        }
        blocks.clone()
    }

    fn inv_cipher(&self, blocks: &mut Vec<Vec<u8>>) -> Vec<u8> {
        let len = blocks.len();
        let mut output: Vec<u8> = Vec::default();
        for (i, block) in blocks.into_iter().enumerate() {
            self.decrypt_block(block);
            if i + 1 == len {
                Self::unpad(block)
            }
            for b in block.clone() {
                output.push(b);
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::AES;

    #[test]
    fn add_round_key() {
        let key = "4A614E645267556B5870327335763879".as_bytes().to_vec();
        let block = &mut vec![
            104, 101, 108, 108, 111, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let ex: Vec<u8> = vec![
            92, 36, 90, 93, 91, 78, 61, 63, 62, 57, 61, 60, 62, 62, 61, 73,
        ];
        let aes = AES::new(key);

        aes.add_round_key(block, 0);

        assert_eq!(ex, block.clone());
    }

    #[test]
    fn shift_rows() {
        let v = &mut vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let ex = vec![1, 6, 11, 16, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12];

        AES::shift_rows(v);

        assert_eq!(ex, v.clone());
    }

    #[test]
    fn mix_columns() {
        let v = &mut vec![1, 6, 11, 16, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12];
        let ex = vec![19, 0, 33, 46, 31, 4, 29, 2, 11, 24, 25, 6, 23, 12, 21, 10];

        AES::mix_columns(v);

        assert_eq!(ex, v.clone());
    }

    #[test]
    fn expansion_of_256_cipher_key() {
        // A.3 Expansion of a 256-bit Cipher Key
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ]
        .to_vec();
        let ex = vec![
            96, 61, 235, 16, 21, 202, 113, 190, 43, 115, 174, 240, 133, 125, 119, 129, 31, 53, 44,
            7, 59, 97, 8, 215, 45, 152, 16, 163, 9, 20, 223, 244, 155, 163, 84, 17, 142, 105, 37,
            175, 165, 26, 139, 95, 32, 103, 252, 222, 168, 176, 156, 26, 147, 209, 148, 205, 190,
            73, 132, 110, 183, 93, 91, 154, 213, 154, 236, 184, 91, 243, 201, 23, 254, 233, 66, 72,
            222, 142, 190, 150, 181, 169, 50, 138, 38, 120, 166, 71, 152, 49, 34, 41, 47, 108, 121,
            179, 129, 44, 129, 173, 218, 223, 72, 186, 36, 54, 10, 242, 250, 184, 180, 100, 152,
            197, 191, 201, 190, 189, 25, 142, 38, 140, 59, 167, 9, 224, 66, 20, 104, 0, 123, 172,
            178, 223, 51, 22, 150, 233, 57, 228, 108, 81, 141, 128, 200, 20, 226, 4, 118, 169, 251,
            138, 80, 37, 192, 45, 89, 197, 130, 57, 222, 19, 105, 103, 108, 204, 90, 113, 250, 37,
            99, 149, 150, 116, 238, 21, 88, 134, 202, 93, 46, 47, 49, 215, 126, 10, 241, 250, 39,
            207, 115, 195, 116, 156, 71, 171, 24, 80, 29, 218, 226, 117, 126, 79, 116, 1, 144, 90,
            202, 250, 170, 227, 228, 213, 155, 52, 154, 223, 106, 206, 189, 16, 25, 13, 254, 72,
            144, 209, 230, 24, 141, 11, 4, 109, 243, 68, 112, 108, 99, 30,
        ];
        let aes = AES::new(key);

        assert_eq!(ex, aes.round_keys);
    }

    #[test]
    fn aes_128_cipher() {
        // C.1 AES-128 (Nk=4, Nr=10)
        // PLAINTEXT: 00112233445566778899aabbccddeeff
        // KEY: 000102030405060708090a0b0c0d0e0f
        let input = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let encrypted_blocks = vec![
            vec![
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a,
            ],
            // padding
            vec![
                149, 79, 100, 242, 228, 232, 110, 158, 238, 130, 210, 2, 22, 104, 72, 153,
            ],
        ];
        let aes = AES::new(key);

        let blocks = &mut aes.cipher(input.clone());
        assert_eq!(encrypted_blocks, blocks.clone());

        let message = aes.inv_cipher(blocks);
        assert_eq!(input, message);
    }

    #[test]
    fn aes_192_cipher() {
        // C.2 AES-192 (Nk=6, Nr=12)
        // PLAINTEXT: 00112233445566778899aabbccddeeff
        // KEY: 000102030405060708090a0b0c0d0e0f1011121314151617
        let input = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let encrypted_blocks = vec![
            vec![
                0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
                0x71, 0x91,
            ],
            // padding
            vec![
                63, 231, 40, 106, 189, 229, 240, 57, 67, 213, 119, 112, 32, 37, 150, 38,
            ],
        ];
        let aes = AES::new(key);

        let blocks = &mut aes.cipher(input.clone());
        assert_eq!(encrypted_blocks, blocks.clone());

        let message = aes.inv_cipher(blocks);
        assert_eq!(input, message);
    }

    #[test]
    fn aes_256_cipher() {
        // C.3 AES-256 (Nk=8, Nr=14)
        // PLAINTEXT: 00112233445566778899aabbccddeeff
        // KEY: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        let input = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let encrypted_blocks: Vec<Vec<u8>> = vec![
            vec![
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89,
            ],
            // padding
            vec![
                159, 59, 117, 4, 146, 111, 139, 211, 110, 49, 24, 233, 3, 164, 205, 74,
            ],
        ];
        let aes = AES::new(key);

        let blocks = &mut aes.cipher(input.clone());
        assert_eq!(encrypted_blocks, blocks.clone());

        let decrypted = aes.inv_cipher(blocks);
        assert_eq!(input, decrypted.clone());
    }
}
