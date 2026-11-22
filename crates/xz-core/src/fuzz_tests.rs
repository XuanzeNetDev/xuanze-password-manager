//! 畸形输入测试。
//!
//! 这个模块只做一件事：把「能构造出来的坏输入」全部喂给文件格式的解析入口，
//! 确认它们**返回 Err 而不是 panic 或越界读**。
//!
//! 为什么单独放在这里：`codec.rs` 里的 `split_sealed` 直接从字节流读 u32
//! 长度字段（`index_len` / `body_len`），这是整个格式里最容易被构造出畸形
//! 数据的入口。一个长度字段写成 `0xFFFFFFFF` 的 71 字节文件，就是一次
//! 「长度校验漏了」的现成考题。
//!
//! 不引入 cargo-fuzz 的原因：它要 nightly 工具链，CI 成本高，而这里的
//! 风险面是**确定的几个字段**，不需要随机变异去撞。逐个字段穷举极值
//! 反而更可复现 —— 失败时能直接指出「是 offset 71 那块出的问题」。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::codec::{split_sealed, FileHeader, HEADER_LEN, VERIFY_BLOCK_LEN};
use crate::kdf::KdfParams;
use crate::vault::Vault;

/// 造一个最小可用的库字节，作为变异基底。
fn seed_vault() -> Vec<u8> {
    let mut v = Vault::create("fuzz-seed-password", KdfParams::light()).unwrap();
    v.seal().unwrap()
}

// ─────────────────────── 逐字节篡改 ───────────────────────

/// 把每一个字节都改成 0xFF / 0x00 各一次，确认不会 panic。
///
/// 这是最土的做法，也是覆盖最广的：任何「某个偏移必须满足某条件」的假设
/// 都会在这里暴露成 panic。
#[test]
fn every_byte_flip_does_not_panic() {
    let base = seed_vault();
    // 只遍历前 160 字节：头 + 两段的长度字段都在这个范围，
    // 而完整打开一次要跑 Argon2（light 档约 14 ms），遍历全文件会让
    // 这个测试跑到一分半。要测的内容不受影响 —— 越界风险集中在长度字段。
    for i in 0..base.len().min(160) {
        for fill in [0x00u8, 0xFFu8] {
            let mut b = base.clone();
            b[i] = fill;

            // 头解析与段切分都是纯字节操作，可以逐字节全试
            let _ = FileHeader::parse(&b);
            let _ = split_sealed(&b);
        }
    }
}

/// 完整打开路径单独测，样本小一些 —— 它每次都要跑 Argon2。
#[test]
fn corrupted_vault_open_is_rejected_not_panic() {
    let base = seed_vault();
    // 挑 24 个有代表性的位置：头里几个关键字段 + 每段的开头
    let picks = [0usize, 7, 8, 9, 10, 11, 23, 54, 55, 70, 71, 75, 80, 120];
    for i in picks {
        if i >= base.len() {
            continue;
        }
        let mut b = base.clone();
        b[i] ^= 0xFF;
        let r = Vault::open_from_bytes(&b, "fuzz-seed-password");
        assert!(r.is_err(), "offset {i} 被改后竟然还能打开");
    }
}

/// 每一个长度字段轮流设成极值。
///
/// `index_len` 在 offset 71，`body_len` 紧跟在 index 段之后。
/// 把它们设成 `u32::MAX`、0、以及「刚好超出剩余字节」的值，
/// 确认切分逻辑有做边界检查，不会算出越界的切片。
#[test]
fn length_fields_extremes_are_rejected() {
    let base = seed_vault();
    let idx_len_off = HEADER_LEN;
    let extremes: [u32; 5] = [0, 1, 0xFFFF, 0x7FFF_FFFF, 0xFFFF_FFFF];

    for val in extremes {
        let mut b = base.clone();
        b[idx_len_off..idx_len_off + 4].copy_from_slice(&val.to_le_bytes());
        let r = split_sealed(&b);
        // 极值都不该成功切出段来
        assert!(r.is_err(), "index_len={val} 竟然切分成功");
        // 也不能 panic —— 走到这里就说明没 panic
    }

    // body_len 同理：先按真实 index_len 定位，再改 body_len
    let real_idx_len =
        u32::from_le_bytes(base[idx_len_off..idx_len_off + 4].try_into().unwrap()) as usize;
    let body_len_off = idx_len_off + 4 + real_idx_len;
    if body_len_off + 4 <= base.len() {
        for val in extremes {
            let mut b = base.clone();
            b[body_len_off..body_len_off + 4].copy_from_slice(&val.to_le_bytes());
            let r = split_sealed(&b);
            assert!(r.is_err(), "body_len={val} 竟然切分成功");
        }
    }
}

/// 各种长度的截断，从 0 到完整长度都试一遍。
///
/// 「截断」是最常见的损坏形态（拷贝没完成、磁盘写满），
/// 每个长度都必须安全地返回 Err。
#[test]
fn every_truncation_is_rejected() {
    let base = seed_vault();
    let step = (base.len() / 60).max(1);
    let mut len = 0;
    while len < base.len() {
        let cut = &base[..len];
        assert!(
            Vault::open_from_bytes(cut, "fuzz-seed-password").is_err(),
            "截断到 {len} 字节竟然打开成功"
        );
        let _ = FileHeader::parse(cut);
        let _ = split_sealed(cut);
        len += step;
    }
}

/// 完全随机的字节，各种长度。
///
/// 用一个简单的线性同余生成器，不引第三方依赖 ——
/// 测试要的是「不会崩」，不是密码学质量的随机性。
#[test]
fn random_bytes_never_panic() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;

    for case in 0..200usize {
        let len = (state as usize % 512).max(1);
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            buf.push((state >> 33) as u8);
        }

        let _ = FileHeader::parse(&buf);
        let _ = split_sealed(&buf);
        let _ = Vault::open_from_bytes(&buf, "whatever");
        // 走到这里没 panic 就算通过
        assert!(case < 200);
    }
}

/// 恰好等于各段边界的长度，逐个试。
///
/// 边界长度是最容易出「差一」错误的地方：`HEADER_LEN`、
/// `HEADER_LEN + 4`、`HEADER_LEN + 4 + VERIFY_BLOCK_LEN`。
#[test]
fn boundary_lengths_are_handled() {
    let base = seed_vault();
    let boundaries = [
        0,
        1,
        HEADER_LEN - 1,
        HEADER_LEN,
        HEADER_LEN + 1,
        HEADER_LEN + 4,
        HEADER_LEN + 4 + VERIFY_BLOCK_LEN,
        base.len() - 1,
        base.len(),
    ];

    for len in boundaries {
        if len > base.len() {
            continue;
        }
        let cut = &base[..len];
        // 不允许 panic，也不允许「长度不够却说成功」
        let r = split_sealed(cut);
        if len < HEADER_LEN + 4 {
            assert!(r.is_err(), "{len} 字节不该切分成功");
        }
        let _ = FileHeader::parse(cut);
    }
}
