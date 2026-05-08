/*++

Licensed under the Apache-2.0 license.

File Name:

    sha1_tests.rs

Abstract:

    File contains test cases for SHA1 API

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{Array4x5, Array4xN, Sha1};

use caliptra_test_harness::test_suite;

const SHA1_HASH_SIZE: usize = 20;

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(hex: &str, buf: &mut [u8]) -> Option<usize> {
    let hex = hex.as_bytes();
    if hex.len() % 2 != 0 {
        return None;
    }
    let n = hex.len() / 2;
    if n > buf.len() {
        return None;
    }
    for i in 0..n {
        let hi = hex_nibble(hex[i * 2])?;
        let lo = hex_nibble(hex[i * 2 + 1])?;
        buf[i] = (hi << 4) | lo;
    }
    Some(n)
}

fn test_sha1(data: &str, expected: Array4x5) {
    let digest = Sha1::new().unwrap().digest(data.as_bytes()).unwrap();
    assert_eq!(digest, expected);
}

fn test_digest0() {
    let expected = Array4xN([0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709]);
    let data = "";
    test_sha1(data, expected);
}

fn test_digest1() {
    let expected = Array4xN([0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d]);
    let data = "abc";
    test_sha1(data, expected);
}

fn test_digest2() {
    let expected = Array4xN([0x84983e44, 0x1c3bd26e, 0xbaae4aa1, 0xf95129e5, 0xe54670f1]);
    let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    test_sha1(data, expected);
}

fn test_digest3() {
    let expected = Array4xN([0xa49b2446, 0xa02c645b, 0xf419f995, 0xb6709125, 0x3a04a259]);
    let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    test_sha1(data, expected);
}

fn test_op1() {
    let expected = Array4xN([0x521d84ef, 0xcae113d0, 0x00a14796, 0x8b508e06, 0x7cb60184]);
    const DATA: [u8; 1000] = [0x61; 1000];
    let mut digest = Array4x5::default();
    let mut sha = Sha1::new().unwrap();
    let mut digest_op = sha.digest_init().unwrap();
    for _ in 0..300 {
        assert!(digest_op.update(&DATA).is_ok());
    }
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, expected);
}

fn test_kat() {
    // Init CFI
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));

    assert!(Sha1::new().is_ok());
}

fn run_aft(hex_msg: &str) {
    let mut buf = [0u8; 5000];
    let len = hex_decode(hex_msg, &mut buf).unwrap();
    let digest = Sha1::new().unwrap().digest(&buf[..len]).unwrap();
    let digest_out = <[u8; SHA1_HASH_SIZE]>::from(digest);
    for byte in digest_out.iter() {
        println!("SHA1:{:02X}", byte);
    }
}

fn run_mct(hex_msg: &str) {
    let mut seed = [0u8; SHA1_HASH_SIZE];
    hex_decode(hex_msg, &mut seed).unwrap();

    let mut a = [0u8; SHA1_HASH_SIZE];
    let mut b = [0u8; SHA1_HASH_SIZE];
    let mut c = [0u8; SHA1_HASH_SIZE];
    let mut msg = [0u8; SHA1_HASH_SIZE * 3];
    let mut digest_out = [0u8; SHA1_HASH_SIZE];

    for ol in 0..100 {
        println!("MCT ol:{}", ol);
        a = seed;
        b = seed;
        c = seed;
        for il in 0..1000 {
            if il % 100 == 0 {
                println!("il:{}", il);
            }
            msg[0..SHA1_HASH_SIZE].copy_from_slice(&a);
            msg[SHA1_HASH_SIZE..SHA1_HASH_SIZE * 2].copy_from_slice(&b);
            msg[SHA1_HASH_SIZE * 2..SHA1_HASH_SIZE * 3].copy_from_slice(&c);
            let digest = Sha1::new().unwrap().digest(&msg).unwrap();
            digest_out = <[u8; SHA1_HASH_SIZE]>::from(digest);
            a = b;
            b = c;
            c = digest_out;
        }
        for byte in digest_out.iter() {
            println!("SHA1:{:02X}", byte);
        }
        seed = digest_out;
    }
}

fn test_sha1_acvp() {
    const CURRENT: &str = include_str!("./vectors/current.txt");
    let mut lines = CURRENT.lines();
    let test_type = lines.next().unwrap().trim();
    let hex_msg = lines.next().unwrap().trim();
    match test_type {
        "AFT" => run_aft(hex_msg),
        "MCT" => run_mct(hex_msg),
        _ => panic!("unknown test type"),
    }
}

test_suite! {
    test_kat,
    test_digest0,
    test_digest1,
    test_digest2,
    test_digest3,
    test_op1,
    test_sha1_acvp,
}
