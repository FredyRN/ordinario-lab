fn main() {
    message("Hola mundo desde una función.");
    let add: i32 = add_two_numbers(7, 9);
    println!("{}", add);
}

fn add_two_numbers (x: i32, y: i32) -> i32 {
    return x + y;
}

fn message(words: &str) {
    println!("{}", words);
}