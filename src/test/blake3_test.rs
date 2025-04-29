// This is an example from https://docs.rs/blake3/latest/blake3/index.html#examples

#[test]
fn blake3_test() {
    // Hash an input all at once.
    let hash1 = blake3::hash(b"foobarbaz");

    // Hash an input incrementally.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"foo");
    hasher.update(b"bar");
    hasher.update(b"baz");
    let hash2 = hasher.finalize();
    assert_eq!(hash1, hash2);

    // Extended output. OutputReader also implements Read and Seek.
    let mut output = [0; 1000];
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut output);
    assert_eq!(hash1, output[..32]);

    // Print a hash as hex.
    // println!("{}", hash1);
}