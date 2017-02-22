extern crate kal;

use kal::gpg::*;
use std::io;

fn main(){
    initialize();
    println!("Started");
    // Create a new context with me as the sender;
    let ctx = PGPContext::new("Nicholas Stone");
    println!("Made Context");
    ctx.set_signer("Nicholas");
    let input = io::stdin();
    println!("Opened Input");
    let mut plain_buf=input.lock();
    let plain_text=GPGData::new(Some(&mut plain_buf));
    match plain_text{
        Ok(text) => {
            match search_keyring("Nicholas", &ctx){
                Some(key_vec)=>{
                    println!("key vec length={}",key_vec.len());
                    let cipher_result=encrypt_PGP(&ctx,&text,&key_vec,true);
                    match cipher_result{
                        Ok(cipher)=> println!("Encrypted message:{}",cipher.read().unwrap()),
                        Err(e)=> panic!(e)
                        }

                },
                None=> panic!("no public key")

            }
        },
        Err(_) => panic!("Reading in plaintext failed")
    }
}
