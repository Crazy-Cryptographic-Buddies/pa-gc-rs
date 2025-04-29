// this file aims to test string read/write
// given a file with a single line, the first number is the number of words
use std::io::{self, BufRead};
use std::fs::File;
use std::path::Path;

#[test]
fn test_string_read_write() {
    // println!("Hello, world!");
    let input_file_name = "src/test/test_string_read.txt";
    let input_file = File::open(input_file_name).unwrap();
    let mut reader = io::BufReader::new(&input_file);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    // println!("{}", line);
    let mut parts = line.split_whitespace();
    let n = parts.next().unwrap().parse::<usize>().unwrap();
    let mut words = Vec::new();
    for _ in 0..n {
        words.push(parts.next().unwrap().to_string());
    }
    println!("{:?}", n);
    println!("{:?}", words);
    println!("This file is located at: {}", file!());
    let dir_path = Path::new(file!()).parent().unwrap();
    println!("This file's parent directory is located at: {}", dir_path.display());
}