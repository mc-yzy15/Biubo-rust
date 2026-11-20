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
    decode_content_with_limit(content, encoding, usize::MAX).unwrap_or_default()
}

/// Decode request content while bounding the decompressed output size.
///
/// Malformed/unsupported encodings preserve the legacy behavior of passing
/// through the original bytes. Exceeding the output limit is an explicit
/// error so callers can reject decompression bombs instead of buffering them.
pub fn decode_content_with_limit(
    content: &[u8],
    encoding: &str,
    max_decoded_size: usize,
) -> Result<Vec<u8>, &'static str> {
    if content.is_empty() || encoding.is_empty() {
        return if content.len() <= max_decoded_size {
            Ok(content.to_vec())
        } else {
            Err("decoded content exceeds size limit")
        };
    }

    let encoding = encoding.to_ascii_lowercase();
    let decoder: Box<dyn Read + '_> = match encoding.as_str() {
        "gzip" => Box::new(GzDecoder::new(content)),
        "deflate" => Box::new(ZlibDecoder::new(content)),
        "br" => Box::new(brotli::Decompressor::new(content, 4096)),
        _ => {
            return if content.len() <= max_decoded_size {
                Ok(content.to_vec())
            } else {
                Err("request content exceeds size limit")
            };
        }
    };

    let read_limit = max_decoded_size.saturating_add(1) as u64;
    let mut decoded = Vec::with_capacity(content.len().min(max_decoded_size));
    match decoder.take(read_limit).read_to_end(&mut decoded) {
        Ok(_) if decoded.len() > max_decoded_size => Err("decoded content exceeds size limit"),
        Ok(_) => Ok(decoded),
        Err(e) => {
            tracing::error!("Decompress failed ({}): {}", encoding, e);
            if content.len() <= max_decoded_size {
                Ok(content.to_vec())
            } else {
                Err("request content exceeds size limit")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_decode_rejects_plain_body_over_limit() {
        assert!(decode_content_with_limit(b"12345", "", 4).is_err());
        assert_eq!(decode_content_with_limit(b"1234", "", 4).unwrap(), b"1234");
    }

    #[test]
    fn bounded_decode_rejects_decompression_bomb_output() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&vec![b'a'; 1024]).unwrap();
        let compressed = encoder.finish().unwrap();

        assert!(decode_content_with_limit(&compressed, "gzip", 128).is_err());
        assert_eq!(
            decode_content_with_limit(&compressed, "gzip", 1024).unwrap(),
            vec![b'a'; 1024]
        );
    }
}
