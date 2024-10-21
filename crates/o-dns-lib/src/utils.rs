// TODO: a more correct approach would be to also take into account the DNS name compression
pub fn get_max_encoded_qname_size(qname: &str) -> usize {
    qname.split(".").fold(1, |acc, label| {
        acc + 1 /* label length */ + label.len()
    })
}
