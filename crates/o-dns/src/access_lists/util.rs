pub(crate) fn find_wildcard_parts(qname: &str) -> impl Iterator<Item = &str> {
    qname
        .split('.')
        .enumerate()
        .skip(1)
        .filter(|(_, label)| !label.is_empty())
        .filter_map(move |(idx, _)| qname.splitn(idx + 1, '.').last())
}
