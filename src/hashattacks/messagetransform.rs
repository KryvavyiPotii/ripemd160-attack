use rand::{thread_rng, Rng, seq::SliceRandom};


fn append_number_to_message(message: &str, num: u64) -> String {
    format!("{message}{num}")
}

fn append_random_number_to_message(message: &str) -> String {
    let maximum_number: u128 = 1 << 100;
    let rand_num: u128 = thread_rng().gen_range(1..maximum_number);

    format!("{message}{rand_num}")
}

fn switch_case(character: char) -> String {
    if character.is_uppercase() {
        character
            .to_lowercase()
            .to_string()
    } else {
        character
            .to_uppercase()
            .to_string()
    }
}

fn generate_random_ascii() -> String {
    thread_rng()
        .gen_range(' '..='~')
        .to_string()
}

fn swap_similar(character: char) -> String {
    let default = "*";
    let mut rng = thread_rng();

    let similar_chars = vec![
        vec!['a', 'A', '@', '4'],
        vec!['b', '6'],
        vec!['B', '%', '&', '8'],
        vec!['c', 'C', '(', '[', '{'],
        vec!['D', 'o', 'O', '0'],
        vec!['e', 'E', '3'],
        vec!['f', '+'],
        vec!['g', 'q', '9', '?'],
        vec!['i', 'I', 'l', 'L', '|', '!', '1'],
        vec!['s', 'S', '$', '5'],
        vec!['t', 'T', '7'],
        vec!['u', 'U', 'v', 'V'],
        vec!['z', 'Z', '2'],
        vec!['-', '=', '~'],
        vec!['\t', ' ', '_']
    ];

    for similar in &similar_chars {
        if similar.contains(&character) {
            let mutation: Vec<&char> = similar
                .iter()
                .filter(|&c| *c != character)
                .collect();

            mutation
                .choose(&mut rng)
                .unwrap()
                .to_string();
        }
    }

    default.to_string()
}

fn transform_message_randomly(message: &str) -> String {
    let mut rng = thread_rng();

    message
        .chars()
        .map(|c| {
            let mutation_type: u32 = rng.gen_range(0..=3);

            match mutation_type {
                0 => switch_case(c),
                1 => generate_random_ascii(),
                2 => swap_similar(c),
                _ => c.to_string(),
            }
        })
        .collect()
}


#[derive(Clone, Debug)]
pub enum MessageTransform {
    AppendRandomNumber,
    Mutate,
    AppendNumberInSequence(u64),
}

impl MessageTransform {
    pub fn transform(&mut self, message: &str) -> String {
        match self {
            Self::AppendRandomNumber =>
                append_random_number_to_message(message),
            Self::Mutate =>
                transform_message_randomly(message),
            Self::AppendNumberInSequence(ref mut num) => {
                *num += 1;
                append_number_to_message(message, *num - 1)
            }
        }
    }
}
