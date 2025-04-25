#[cfg(test)]
mod tests {
    use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;

    fn run(circuit_file_name: &String) {
        let bristol_fashion_adaptor = BristolFashionAdaptor::new(
            circuit_file_name,
        );
    }
    
    #[test]
    fn test_pa_2pc_for_addition() {
        
    }
}