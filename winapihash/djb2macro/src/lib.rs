use djb2::djb2_hash;
use proc_macro::TokenStream;
use proc_macro2::Literal;
use quote::quote;
use syn::{
    parse_macro_input,
    LitStr,
};

// Calculate DJB2 hash of string at compile time
#[proc_macro]
pub fn djb2(input: TokenStream) -> TokenStream {
    println!("Invoked djb2 macro");
    let parsed = parse_macro_input!(input as LitStr);
    let string_to_hash = parsed.value();
    let hash = djb2_hash(string_to_hash.as_bytes());
    let hash_literal = Literal::u32_suffixed(hash);

    // Replace token with hash literal
    quote! {
        #hash_literal
    }.into()
}

