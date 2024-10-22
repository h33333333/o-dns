use std::collections::HashMap;

pub fn get_max_encoded_qname_size(
    qname: &str,
    label_cache: Option<&HashMap<&str, usize>>,
) -> usize {
    let mut size = 0;
    for (idx, label) in qname.split(".").enumerate() {
        if !label.is_empty() {
            if let Some(cache) = label_cache.as_deref() {
                let remaining_qname = qname.splitn(idx + 1, '.').last().unwrap();
                if cache.contains_key(remaining_qname) {
                    return size + 2 /* JUMP PTR bytes */;
                }
            }
            size += 1 /* label length */ + label.len();
        }
    }
    // Account for the null byte
    size + 1
}
