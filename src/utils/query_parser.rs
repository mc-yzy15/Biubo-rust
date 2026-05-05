pub const VALID_FIELDS: &[&str] = &[
    "request_id",
    "type",
    "attack_types",
    "time",
    "ip",
    "cdn_ip",
    "country",
    "city",
    "fingerprint",
    "method",
    "url",
    "headers",
    "content",
];

#[derive(Debug, Clone, PartialEq)]
pub enum AstNode {
    Field {
        field: String,
        op: FieldOp,
        value: FieldValue,
    },
    Not(Box<AstNode>),
    Binary {
        op: BinOp,
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldOp {
    Eq,
    Fuzzy,
    In,
    #[allow(dead_code)]
    Range,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Str(String),
    List(Vec<String>),
    #[allow(dead_code)]
    Range(String, String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinOp {
    And,
    Or,
}

#[derive(Debug, Clone)]
enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    In,
    Field { raw: String },
}

pub fn parse(query: &str) -> Result<AstNode, String> {
    let tokens = tokenize(query)?;
    let mut parser = Parser::new(&tokens);
    parser.parse_expr()
}

pub fn evaluate(node: &AstNode, record: &serde_json::Value) -> bool {
    match node {
        AstNode::Binary { op, left, right } => {
            let l = evaluate(left, record);
            let r = evaluate(right, record);
            match op {
                BinOp::And => l && r,
                BinOp::Or => l || r,
            }
        }
        AstNode::Not(operand) => !evaluate(operand, record),
        AstNode::Field { field, op, value } => {
            let actual_field = if field == "content" {
                "data"
            } else {
                field.as_str()
            };
            let raw_val = record.get(actual_field);
            let rec_str = flatten(raw_val);
            let is_container = raw_val
                .map(|v| v.is_object() || v.is_array())
                .unwrap_or(false);

            match op {
                FieldOp::Eq => {
                    if let FieldValue::Str(pattern) = value {
                        let escaped = regex::escape(pattern).replace(r"\*", ".*");
                        let re = regex::Regex::new(&format!("(?i)^{}$", escaped)).unwrap();
                        re.is_match(&rec_str)
                    } else {
                        false
                    }
                }
                FieldOp::Fuzzy => {
                    if let FieldValue::Str(pattern) = value {
                        rec_str.to_lowercase().contains(&pattern.to_lowercase())
                    } else {
                        false
                    }
                }
                FieldOp::In => {
                    if let FieldValue::List(values) = value {
                        if is_container {
                            values
                                .iter()
                                .any(|v| rec_str.to_lowercase().contains(&v.to_lowercase()))
                        } else {
                            values.iter().any(|v| v.eq_ignore_ascii_case(&rec_str))
                        }
                    } else {
                        false
                    }
                }
                FieldOp::Range => {
                    if let FieldValue::Range(start, end) = value {
                        rec_str.as_str() >= start.as_str() && rec_str.as_str() <= end.as_str()
                    } else {
                        false
                    }
                }
            }
        }
    }
}

fn flatten(val: Option<&serde_json::Value>) -> String {
    match val {
        Some(serde_json::Value::Object(map)) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}:{}", k, flatten(Some(v))))
                .collect();
            parts.join(" ")
        }
        Some(serde_json::Value::Array(arr)) => {
            let parts: Vec<String> = arr.iter().map(|v| flatten(Some(v))).collect();
            parts.join(" ")
        }
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

fn tokenize(query: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = query.chars().peekable();

    while let Some(&ch) = chars.peek() {
        match ch {
            '(' => {
                tokens.push(Token::LParen);
                chars.next();
            }
            ')' => {
                tokens.push(Token::RParen);
                chars.next();
            }
            ' ' | '\t' | '\n' => {
                chars.next();
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '(' || c == ')' || c.is_whitespace() {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }

                match word.to_uppercase().as_str() {
                    "AND" => tokens.push(Token::And),
                    "OR" => tokens.push(Token::Or),
                    "NOT" => tokens.push(Token::Not),
                    "IN" => tokens.push(Token::In),
                    _ => {
                        if word.contains(':') {
                            tokens.push(Token::Field { raw: word });
                        } else {
                            return Err(format!("Unrecognized token: {}", word));
                        }
                    }
                }
            }
        }
    }

    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: &[Token]) -> Self {
        Parser {
            tokens: tokens.to_vec(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        let tok = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        tok
    }

    fn parse_expr(&mut self) -> Result<AstNode, String> {
        let mut node = self.parse_term()?;
        while let Some(Token::Or) = self.peek() {
            self.advance();
            let right = self.parse_term()?;
            node = AstNode::Binary {
                op: BinOp::Or,
                left: Box::new(node),
                right: Box::new(right),
            };
        }
        Ok(node)
    }

    fn parse_term(&mut self) -> Result<AstNode, String> {
        let mut node = self.parse_unary()?;
        while let Some(Token::And) = self.peek() {
            self.advance();
            let right = self.parse_unary()?;
            node = AstNode::Binary {
                op: BinOp::And,
                left: Box::new(node),
                right: Box::new(right),
            };
        }
        Ok(node)
    }

    fn parse_unary(&mut self) -> Result<AstNode, String> {
        if let Some(Token::Not) = self.peek() {
            self.advance();
            let operand = self.parse_unary()?;
            Ok(AstNode::Not(Box::new(operand)))
        } else {
            self.parse_atom()
        }
    }

    fn parse_atom(&mut self) -> Result<AstNode, String> {
        match self.peek() {
            Some(Token::LParen) => {
                self.advance();
                let node = self.parse_expr()?;
                match self.advance() {
                    Some(Token::RParen) => Ok(node),
                    _ => Err("Expected closing parenthesis".to_string()),
                }
            }
            Some(Token::Field { .. }) => {
                if let Some(Token::Field { raw }) = self.advance() {
                    parse_field_token(&raw)
                } else {
                    Err("Unexpected end of input".to_string())
                }
            }
            _ => Err("Expected field or left parenthesis".to_string()),
        }
    }
}

fn parse_field_token(raw: &str) -> Result<AstNode, String> {
    let colon_pos = raw
        .find(':')
        .ok_or_else(|| format!("Invalid field token: {}", raw))?;
    let fname = &raw[..colon_pos];
    let rest = &raw[colon_pos + 1..];

    if !VALID_FIELDS.contains(&fname.to_lowercase().as_str()) {
        return Err(format!(
            "Unknown field '{}', supported: {:?}",
            fname, VALID_FIELDS
        ));
    }

    if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
        let inner = &rest[1..rest.len() - 1];
        if let Some(stripped) = inner.strip_prefix('~') {
            return Ok(AstNode::Field {
                field: fname.to_lowercase(),
                op: FieldOp::Fuzzy,
                value: FieldValue::Str(stripped.to_string()),
            });
        }
        return Ok(AstNode::Field {
            field: fname.to_lowercase(),
            op: FieldOp::Eq,
            value: FieldValue::Str(inner.to_string()),
        });
    }

    let in_re = regex::Regex::new(r"(?i)^IN\(([^)]+)\)$").unwrap();
    if let Some(captures) = in_re.captures(rest) {
        let values: Vec<String> = captures[1]
            .split(',')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect();
        return Ok(AstNode::Field {
            field: fname.to_lowercase(),
            op: FieldOp::In,
            value: FieldValue::List(values),
        });
    }

    if let Some(stripped) = rest.strip_prefix('~') {
        return Ok(AstNode::Field {
            field: fname.to_lowercase(),
            op: FieldOp::Fuzzy,
            value: FieldValue::Str(stripped.to_string()),
        });
    }

    Ok(AstNode::Field {
        field: fname.to_lowercase(),
        op: FieldOp::Eq,
        value: FieldValue::Str(rest.to_string()),
    })
}
