// this file aims to test string read/write
// given a file with a single line, the first number is the number of words
use std::io::{self, BufRead, Write};
use std::fs::File;

#[test]
fn test_string_read_write() {
    println!("Hello, world!");
    let input_file_name = "/test/test_string_read.txt";
    let input_file = File::open(input_file_name).unwrap();
    let mut reader = io::BufReader::new(&input_file);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    println!("{}", line);
}