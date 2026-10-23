//! State-free conformance adapter; never installed with the host bundle.
use clap::Parser;
use std::io::{self, BufRead, Write};
#[derive(Parser)]
struct Args {}
fn main() -> io::Result<()> {
    Args::parse();
    let mut input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut line = Vec::new();
    let mut overflow = false;
    loop {
        let bytes = input.fill_buf()?;
        if bytes.is_empty() {
            if !line.is_empty() || overflow {
                emit(&mut output, &line, overflow)?;
            }
            return Ok(());
        }
        let end = bytes.iter().position(|b| *b == b'\n').map(|i| i + 1);
        let n = end.unwrap_or(bytes.len());
        if line.len() + n > 2 << 20 {
            overflow = true;
            line.clear();
        } else if !overflow {
            line.extend_from_slice(&bytes[..n]);
        }
        input.consume(n);
        if end.is_some() {
            emit(&mut output, &line, overflow)?;
            line.clear();
            overflow = false;
        }
    }
}
fn emit(out: &mut impl Write, data: &[u8], overflow: bool) -> io::Result<()> {
    let response = if overflow {
        serde_json::json!({"ok":false,"code":"invalid"})
    } else {
        peerspan_host::linking::probe(data)
    };
    serde_json::to_writer(&mut *out, &response)?;
    out.write_all(b"\n")?;
    out.flush()
}
