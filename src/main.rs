fn main() {
    let add_two_n: i32 = add_two_numbers(3, 6);
    println!("= {}", add_two_n);
    let plus_tree_result: i32 = plus_tree(add_two_n);
    println!("{} plus tree is {}", add_two_n, plus_tree_result);
}

fn add_two_numbers(x: i32, y: i32) -> i32 {
    println!("Adding {} to {}", x, y);
    x + y
}

fn plus_tree(n: i32) -> i32 {
    println!("Adding 3 to: {}", n);
    n + 3
}
