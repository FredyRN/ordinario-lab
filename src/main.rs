struct Person {
    name: String,
    movies: u8,
}

struct Genre {
    genre: String,
    description: String,
}

struct Movie {
    name: String,
    duration: u8,
    author: Person,
    genre: Genre,
    year: u16,
}

fn main() {
    let fredyr_n: Person = Person {
        name: String::from("Fredy Rodriguez"),
        movies: 3,
    };
    let animation: Genre = Genre {
        genre: String::from("Anime"),
        description: String::from("Tipo de película o animacion gráfica en capítulos cortos."),
    };
    let white_nights: Movie = Movie {
        name: String::from("White nights"),
        duration: 90,
        author: fredyr_n,
        genre: animation,
        year: 1995,
    };
    println!(
        "Película: {}, Autor: {}, {} minutos. Género: {}. Año: {}",
        white_nights.name,
        white_nights.author.name,
        white_nights.duration,
        white_nights.genre.genre,
        white_nights.year
    );
}
