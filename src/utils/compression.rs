use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};

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

pub fn decompress_json(data: &[u8]) -> serde_json::Value {
    if data.is_empty() {
        return serde_json::json!({});
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

#[allow(dead_code)]
pub fn encode_content(content: &[u8], encoding: &str) -> Vec<u8> {
    if content.is_empty() || encoding.is_empty() {
        return content.to_vec();
    }

    match encoding.to_lowercase().as_str() {
        "gzip" => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
            if encoder.write_all(content).is_ok() {
                if let Ok(compressed) = encoder.finish() {
                    return compressed;
                }
            }
            content.to_vec()
        }
        "deflate" => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
            if encoder.write_all(content).is_ok() {
                if let Ok(compressed) = encoder.finish() {
                    return compressed;
                }
            }
            content.to_vec()
        }
        "br" => {
            let mut compressed = Vec::new();
            {
                let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 11, 22);
                if writer.write_all(content).is_err() {
                    return content.to_vec();
                }
            }
            compressed
        }
        _ => content.to_vec(),
    }
}
