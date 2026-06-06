pub mod compression;
pub mod crypto;
pub mod http_utils;
pub mod query_parser;
pub mod ua_parser;
pub mod url_validator;

pub trait RoundTo {
    fn round_to(self, decimals: u32) -> f64;
}

impl RoundTo for f64 {
    fn round_to(self, decimals: u32) -> f64 {
        let factor = 10f64.powi(decimals as i32);
        (self * factor).round() / factor
    }
}
