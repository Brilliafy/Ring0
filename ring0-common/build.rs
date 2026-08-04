use std::path::{Path, PathBuf};

fn snake_to_camel(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut upper_next = false;
    for c in s.chars() {
        if c == '_' {
            upper_next = true;
        } else if upper_next {
            result.push(c.to_ascii_uppercase());
            upper_next = false;
        } else {
            result.push(c);
        }
    }
    result
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    capnpc::CompilerCommand::new()
        .file("../schema/event.capnp")
        .run()
        .expect("capnp schema compilation failed");

    let generated = find_file(Path::new(&out_dir), "event_capnp.rs");

    if let Some(src) = generated {
        let content = std::fs::read_to_string(&src).unwrap();
        let content = content.replace("crate::event_capnp::", "crate::proto::");

        let mut lines: Vec<String> = Vec::new();
        for line in content.lines() {
            let mut l = line.to_string();
            if (l.contains("pub fn set_")
                || l.contains("pub fn get_")
                || l.contains("pub fn init_"))
                && !l.contains("field_type")
                && !l.contains("annotation_type")
            {
                if let Some(fn_start) = l.find("pub fn ") {
                    let rest = &l[fn_start + 7..];
                    if let Some(paren) = rest.find('(') {
                        let fn_name = &rest[..paren];
                        if fn_name.contains('_') {
                            let camel = snake_to_camel(fn_name);
                            l = l.replace(fn_name, &camel);
                        }
                    }
                }
            }
            lines.push(l);
        }
        let content = lines.join("\n");

        let dst = Path::new(&out_dir).join("event_capnp.rs");
        std::fs::write(&dst, &content).unwrap();
    }

    println!("cargo:rerun-if-changed=../schema/event.capnp");
}

fn find_file(dir: &Path, target: &str) -> Option<PathBuf> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = find_file(&path, target) {
                    return Some(found);
                }
            } else if path.file_name().and_then(|n| n.to_str()) == Some(target) {
                return Some(path);
            }
        }
    }
    None
}
