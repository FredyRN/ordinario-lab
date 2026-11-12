fn main() {
    let greeting: &str = "mundo!";
    let min_i8: i8 = i8::MIN;
    let max_i8: i8 = i8::MAX;
    let min_i128: i128 = i128::MIN;
    let max_i128: i128 = i128::MAX;
    let max_u128: u128 = u128::MAX;

    let tuple_one: (u8, char, bool) = (1, 'K', true);

    let array_one: [u8; 4] = [0, 8, 0, 6];

    let word_one: String = String::from("Hola, ");
    let sentence: String = word_one + greeting;

    let char_a: char = 'a';

    println!("{greeting}");
    println!("Min i8: {min_i8} -- {max_i8}");
    println!("Min i128: {min_i128} -- {max_i128}");
    println!("Max u128: {max_u128}");
    println!("Char {char_a}");
    println!("{}", tuple_one.1);
    println!("{}", array_one[1]);

    println!("{sentence}");

    // Conditionals
    let grade: u8 = 5;
    if grade == 5 {
        println!("Eureka, aprobaste con calificación perfecta.")
    } else if (3..=4).contains(&grade) {
        println!("Aprobaste, pero puedes mejorar.")
    } else {
        println!("No aprueba.")
    }

    // Match
    let day_of_week: String = String::from("Monday");
    match day_of_week.as_str() {
        "Monday" => println!("Hoy es lunes."),
        "Tuesday" => println!("Hoy es martes."),
        "Wednesday" => println!("Hoy es miércoles."),
        _ => println!("Día de la semana no existe."),
    }

    let grade: u8 = 4;
    match grade {
        5 => println!("Eureka, aprobaste con calificación perfecta."),
        4 => println!("Aprobaste, pero puedes mejorar."),
        3 => println!("Aprobaste, pero puedes mejorar."),
        _ => println!("No apruebas."),
    }

    // loops
    let mut number: u8 = 10;
    loop {
        println!("Infinite loop: {}", number);
        number -= 1;
        if number == 0 {
            println!("Infinite loop closed.");
            break;
        }
    }

    // While
    let mut number: u8 = 10;
    while number > 0 {
        println!("Number while: {}", number);
        number -= 1;
    }

    // for
    for num in 1..=10 {
        println!("For number {}", num);
    }
    let fruits: [&str; 3] = ["Apple", "Pie", "Pineaple"];
    for fruit in fruits.iter() {
        if *fruit == "Pie" {
            continue;
        }
        println!("I like to eat {}", fruit);
    }
}
