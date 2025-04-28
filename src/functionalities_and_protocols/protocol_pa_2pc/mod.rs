mod test;
mod prover_in_pa_2pc;

fn post_increase(value: &mut usize) -> usize {
    let original_value = value.clone();
    *value += 1usize;
    original_value
}