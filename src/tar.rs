//! The uncompressed pax tar that workspace archives use (runtime task
//! contract, Packing): each entry is a pax extended header carrying its
//! `path` (and `linkpath`), then the ustar header.
use std::io::Write;

/// A directory entry.
pub const DIRECTORY: u8 = b'5';
/// A symbolic link entry.
pub const SYMLINK: u8 = b'2';
/// A regular file entry.
pub const FILE: u8 = b'0';

/// Writes one entry's headers; a regular file's `size` bytes and their
/// padding (`pad`) follow.
pub fn entry(
    out: &mut impl Write,
    path: &[u8],
    kind: u8,
    mode: u32,
    size: u64,
    link: &[u8],
) -> std::io::Result<()> {
    let mut records = record(b"path", path);
    if !link.is_empty() {
        records.extend(record(b"linkpath", link));
    }
    header(out, b"PaxHeader", b'x', 0o644, records.len() as u64, b"")?;
    out.write_all(&records)?;
    out.write_all(&vec![0; (512 - records.len() % 512) % 512])?;
    header(out, path, kind, mode, size, link)
}
/// The zero padding after `size` bytes of file data.
pub fn pad(out: &mut impl Write, size: u64) -> std::io::Result<()> {
    out.write_all(&vec![0; (512 - (size % 512) as usize) % 512])
}
/// The end-of-archive marker.
pub fn end(out: &mut impl Write) -> std::io::Result<()> {
    out.write_all(&[0; 1024])
}
/// A pax record, `"<length> <key>=<value>\n"`, whose length counts itself.
fn record(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(key.len() + value.len() + 3);
    body.push(b' ');
    body.extend_from_slice(key);
    body.push(b'=');
    body.extend_from_slice(value);
    body.push(b'\n');
    let mut length = body.len() + 1;
    while length.to_string().len() + body.len() != length {
        length += 1;
    }
    let mut out = length.to_string().into_bytes();
    out.extend(body);
    out
}
fn header(
    out: &mut impl Write,
    name: &[u8],
    kind: u8,
    mode: u32,
    size: u64,
    link: &[u8],
) -> std::io::Result<()> {
    let mut h = [0u8; 512];
    let put = |h: &mut [u8; 512], at: usize, len: usize, text: &[u8]| {
        let n = text.len().min(len);
        h[at..at + n].copy_from_slice(&text[..n]);
    };
    let octal = |h: &mut [u8; 512], at: usize, len: usize, value: u64| {
        let text = format!("{value:0width$o}", width = len - 1);
        h[at..at + len - 1].copy_from_slice(&text.as_bytes()[text.len() - (len - 1)..]);
    };
    put(&mut h, 0, 100, name);
    octal(&mut h, 100, 8, u64::from(mode));
    octal(&mut h, 108, 8, 0);
    octal(&mut h, 116, 8, 0);
    octal(&mut h, 124, 12, size);
    octal(&mut h, 136, 12, 0);
    h[156] = kind;
    put(&mut h, 157, 100, link);
    put(&mut h, 257, 6, b"ustar\0");
    put(&mut h, 263, 2, b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
    let text = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(text.as_bytes());
    out.write_all(&h)
}
