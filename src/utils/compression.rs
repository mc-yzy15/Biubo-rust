use std::io::{Read, Write};

use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::ZlibEncoder;
use flate2::Compression;

pub fn compress_json(data: &serde_json::Value) -> Vec<u8> {
    let packed = match rmp_serde::to_vec(data) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("compress_json failed: {}", e);
            return serde_json::to_string(data).unwrap_or_default().into_bytes();
        }
    };

    let mut zlib_encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    if zlib_encoder.write_all(&packed).is_ok() {
        if let Ok(zlibbed) = zlib_encoder.finish() {
            if zlibbed.len() < packed.len() {
                return zlibbed;
            }
        }
    }

    let mut result = vec![b'm'];
    result.extend_from_slice(&packed);
    result
}

/// 将 JSON 值压缩为可安全存入 JSON 字符串的文本形式（hex 编码，带 `hex:` 前缀）。
///
/// 压缩产物是任意二进制字节，不能直接用 `String::from_utf8_lossy` 转字符串
/// （会破坏数据导致解压失败），必须使用无损的文本编码。
pub fn compress_json_to_string(data: &serde_json::Value) -> String {
    format!("hex:{}", hex::encode(compress_json(data)))
}

pub fn decompress_json(data: &[u8]) -> serde_json::Value {
    if data.is_empty() {
        return serde_json::json!({});
    }

    // 文本形式存储的压缩数据（见 compress_json_to_string）
    if let Some(hex_str) = data.strip_prefix(b"hex:") {
        return match hex::decode(hex_str) {
            Ok(bytes) => decompress_json(&bytes),
            Err(e) => {
                tracing::error!("decompress_json (hex decode) failed: {}", e);
                serde_json::json!({})
            }
        };
    }

    if data[0] == b'm' {
        return match rmp_serde::from_slice(&data[1..]) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("decompress_json (msgpack) failed: {}", e);
                serde_json::json!({})
            }
        };
    }

    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    match decoder.read_to_end(&mut decompressed) {
        Ok(_) => match rmp_serde::from_slice(&decompressed) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("decompress_json (zlib+msgpack) failed: {}", e);
                serde_json::json!({})
            }
        },
        Err(e) => {
            tracing::error!("decompress_json (zlib) failed: {}", e);
            serde_json::json!({})
        }
    }
}

pub fn decode_content(content: &[u8], encoding: &str) -> Vec<u8> {
    if content.is_empty() || encoding.is_empty() {
        return content.to_vec();
    }

    match encoding.to_lowercase().as_str() {
        "gzip" => {
            let mut decoder = GzDecoder::new(content);
            let mut decoded = Vec::new();
            match decoder.read_to_end(&mut decoded) {
                Ok(_) => decoded,
                Err(e) => {
                    tracing::error!("Decompress failed (gzip): {}", e);
                    content.to_vec()
                }
            }
        }
        "deflate" => {
            let mut decoder = ZlibDecoder::new(content);
            let mut decoded = Vec::new();
            match decoder.read_to_end(&mut decoded) {
                Ok(_) => decoded,
                Err(e) => {
                    tracing::error!("Decompress failed (deflate): {}", e);
                    content.to_vec()
                }
            }
        }
        "br" => {
            let mut decoded = Vec::new();
            let mut decoder = brotli::Decompressor::new(content, 4096);
            match decoder.read_to_end(&mut decoded) {
                Ok(_) => decoded,
                Err(e) => {
                    tracing::error!("Decompress failed (br): {}", e);
                    content.to_vec()
                }
            }
        }
        _ => content.to_vec(),
    }
}
