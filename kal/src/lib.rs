extern crate gpgme;
extern crate libc;
pub mod gpg {
    use gpgme;
    use gpgme::{gpgme_ctx_t,gpgme_new, gpgme_set_protocol, gpgme_protocol_t,
                gpgme_set_sender,gpgme_set_armor, gpgme_data_t,gpgme_data_new_from_mem, gpgme_key_t,
                gpgme_op_keylist_start, gpgme_op_keylist_next, gpgme_data_release, gpgme_data_new, gpgme_op_decrypt,
                gpgme_data_read, gpgme_release, gpgme_key_unref, gpgme_set_pinentry_mode, gpgme_pinentry_mode_t, gpgme_engine_info_t, gpgme_get_engine_info, gpgme_strerror, gpgme_error_t, gpgme_check_version, gpgme_data_seek, gpgme_op_encrypt, gpgme_encrypt_flags_t,gpgme_signers_add, gpgme_op_encrypt_sign};
    use std::mem;
    use std::os;
    use std::io;
    use std::ops;
    use std::io::BufRead;
    use std::ptr;
    use std::string::FromUtf8Error;
    use libc;

    pub fn initialize(){
        unsafe{
            gpgme_check_version(ptr::null());
        }
    }
    
    pub struct PGPContext{
        context: gpgme_ctx_t,
        context_ref: *mut gpgme_ctx_t
    }

    impl ops::Drop for PGPContext{
	fn drop(&mut self){
	    unsafe{
		gpgme_release(self.context);
                libc::free(self.context_ref as *mut libc::c_void);
	    }
	}
    }
    
    impl PGPContext{
	pub fn new(sender: &str) -> PGPContext{
	    unsafe{
		//Create Context
                println!("Only need to allocate {} bytes for pgp context", mem::size_of::<gpgme_ctx_t>());
                let ctx_ref: *mut gpgme_ctx_t=libc::malloc(1000) as *mut gpgme_ctx_t;
		let ctx_error=gpgme_new(ctx_ref);
                println!("Context error={}",error_to_string(ctx_error).unwrap());
                let ctx=*ctx_ref;
		let addr_string: String=String::from(sender);
		let init: os::raw::c_char=0;
		//Add check that the address isn't too big
		let mut addr_array=[init;200];
		let mut i=0;
		for c in addr_string.chars(){
		    addr_array[i]=c as i8;	
		    i=i+1;
		}
		//Set protocol to OpenPGP
		let protocol_error=gpgme_set_protocol (ctx, gpgme_protocol_t::GPGME_PROTOCOL_OpenPGP);
                println!("Protocol error={}",error_to_string(protocol_error).unwrap());
		//Set Sender
		gpgme_set_sender(ctx,&addr_array[0] as *const os::raw::c_char);
		//Enable Ascii Armor
		gpgme_set_armor (ctx, 1);

                //Force use of pinentry

                //gpgme_set_pinentry_mode(ctx,gpgme_pinentry_mode_t::GPGME_PINENTRY_MODE_ASK);
                println!("about to get engine info");
                let engine_info_ref: *mut gpgme_engine_info_t=libc::malloc(1000) as *mut gpgme_engine_info_t;
                gpgme_get_engine_info(engine_info_ref);
                println!("Just got engine info");

                PGPContext{context:ctx,context_ref:ctx_ref}
	    }
	}
        pub fn set_signer(&self,sign_addr:&str){
            unsafe{
                let sign:PGPKey=search_keyring(sign_addr,self).expect("Can't set signer").pop().unwrap();

                let add_sign_err=gpgme_signers_add (self.context, sign.key);
                println!("add signer: {}",error_to_string(add_sign_err).unwrap());
            }
        }
    }

    pub struct GPGData{
	data: gpgme_data_t,
        pointer: *mut gpgme_data_t
    }
    impl GPGData{
	//Pass Some() to read a BufRead into the new GPGData or None for an empty object
	pub fn new(plaintext_option: Option<&mut BufRead>) -> io::Result<GPGData>{
            let mut buf_vec:Vec<u8>=Vec::new();
	    unsafe {
	        let mut dh_ref: *mut gpgme_data_t = libc::malloc(1000000) as *mut gpgme_data_t;
	        match plaintext_option{
                    Some(plaintext) => {
                        match plaintext.read_to_end(&mut buf_vec) {
		            Ok(size) => {
			        
			        let new_data_err=gpgme_data_new_from_mem(dh_ref, buf_vec.as_mut_slice().as_ptr() as *const os::raw::c_char, size, 1);
                                println!("New data error={}",error_to_string(new_data_err).unwrap());
                                Result::Ok(GPGData{data: *dh_ref, pointer: dh_ref})
		            },
		            Err(e) => Result::Err(e)
		        }
                        
                    },
                    None => {
                        let new_empty_data_err=gpgme_data_new(dh_ref);
                        println!("New empty data: {}",error_to_string(new_empty_data_err).unwrap());
                        Ok(GPGData{data: *dh_ref, pointer: dh_ref})
                    }
                }
	    }
	    
	}
        pub fn read(&self) -> Result<String, &'static str>{
            let mut self_string=String::new();
            unsafe{
                gpgme_data_seek(self.data, 0, libc::SEEK_SET);
	        let buf_ptr = libc::malloc(1000) as *mut os::raw::c_void;
	        loop{
		    let size=gpgme_data_read(self.data, buf_ptr, 1000);
                    println!("size={}",size);         
                    if size==0{
                        break;
                    }
                    let read_result:Result<String, FromUtf8Error>=c_str_to_string(buf_ptr as *mut os::raw::c_char, Some(size));
                    match read_result{
                        Ok(partial) => {self_string.push_str(&partial);
                                        //println!("partial message={}",partial)
                        },
                        Err(_) => return Err("Error Reading Plaintext!!")
	            }
                    
                }
                libc::free(buf_ptr as *mut libc::c_void);
            }
            Ok(self_string)
        }
    }impl Drop for GPGData{
        fn drop(&mut self){
	    unsafe{
	        gpgme_data_release (self.data);
                libc::free(self.pointer as *mut libc::c_void);
	    }
        }
    }


    pub struct PGPKey{
        key: gpgme_key_t,
        key_ptr: *mut gpgme_key_t
    }
    impl Drop for PGPKey{
        fn drop(&mut self){
            unsafe{
                gpgme_key_unref(self.key);
                libc::free(self.key_ptr as *mut libc::c_void);
            }
        }
    }

    pub fn search_keyring(pattern: &str, ctx:&PGPContext) -> Option<Vec<PGPKey>> {
        unsafe{
            let mut pattern_vec=pattern.as_bytes();
            let mut pattern_array: [os::raw::c_char;100] = [0 as os::raw::c_char; 100];
            let mut index=0;
            for b in pattern_vec.iter(){
                pattern_array[index]=*b as i8;
                index=index+1;
            }
	    gpgme_op_keylist_start (ctx.context, pattern_array.as_ptr(), 0);
	    let mut key_vec: Vec<PGPKey> = Vec::new();
	    let mut found_key:bool = false;
            let mut key_ref = libc::malloc(8) as *mut gpgme_key_t;
	    loop{
	        let err=gpgme_op_keylist_next(ctx.context, key_ref);
                let raw_key=*key_ref;
	        println!("keylist err={}",error_to_string(err).unwrap());
                match error_to_string(err){
		    Ok(s) => {
                        if s.contains("Success"){
                            key_vec.push(PGPKey{ key: raw_key, key_ptr: key_ref});
			    found_key = true;
                            println!("Found a key")
                        }else{
                            break;
                        }
                    },
                    _ => break
                }

	    }
            
	    if found_key{
	        return Some(key_vec);
	    }else{
                None
            }
            
        }
    }
    pub fn decrypt_PGP(ctx: &PGPContext, ciphertext: &GPGData) -> Result<GPGData,String>{
        //gpgme_op_decrypt (gpgme_ctx_t ctx, gpgme_data_t cipher, gpgme_data_t plain);
        let mut plaintext_string: String= String::new();		
        unsafe{
            let plaintext: GPGData = GPGData::new(None).unwrap();
            let decrypt_error: u32 = gpgme_op_decrypt(ctx.context, ciphertext.data, plaintext.data);

            println!("Decrypt error={}",error_to_string(decrypt_error).unwrap());
            match decrypt_error{
                0 => Ok(plaintext),
                _ => Err(error_to_string(decrypt_error).unwrap())
            }
        }
    }

    pub fn encrypt_PGP(ctx:&PGPContext,plain:&GPGData,rec:&Vec<PGPKey>,sign: bool)->Result<GPGData, String>{
        let cipher=GPGData::new(None).expect("Failed to create empty GPGData");
        //Add check that the provided context has at least one signer
        unsafe{
            let mut rec_array: [gpgme_key_t; 32] = [0 as u64 as gpgme_key_t; 32];
            for i in 0..rec.len(){
                rec_array[i]=rec[i].key;
            }
            let mut encrypt_error= 0 as gpgme_error_t;
            if(sign){
                encrypt_error=gpgme_op_encrypt_sign(ctx.context, rec_array.as_mut_ptr(), gpgme_encrypt_flags_t::GPGME_ENCRYPT_ALWAYS_TRUST, plain.data, cipher.data);
            }else{
                encrypt_error=gpgme_op_encrypt(ctx.context, rec_array.as_mut_ptr(), gpgme_encrypt_flags_t::GPGME_ENCRYPT_ALWAYS_TRUST, plain.data, cipher.data);
            }
            if(error_to_string(encrypt_error).unwrap().contains("Success")){
                Ok(cipher)
            }else{
                Err(String::from("Encryption Failed"))
            }
        }
    }


    fn error_to_string(err:gpgme_error_t) -> Result<String, FromUtf8Error> {
        unsafe{
            let mut err_str_ref: *const os::raw::c_char=gpgme_strerror(err);
            c_str_to_string(err_str_ref,None)
        }
        
    }
    //If length is None, read to first null byte, otherwise read length bytes
    fn c_str_to_string(c_str:*const os::raw::c_char, length: Option<isize>) -> Result<String, FromUtf8Error>{
        let mut str_vec:Vec<u8>=Vec::new();
        //Print error string
        unsafe{
            let mut index=0;
            loop{
                if length.is_some(){
                    if index>=length.expect("Length isn't some"){
                        break;
                    }
                }
                match *c_str.offset(index){
                    0 => break,
                    _ => str_vec.push(*c_str.offset(index) as u8)
                    // println!("{}",*err_str_ref);
                        
                        
                }
                index=index+1;
                
            }
        }
        String::from_utf8(str_vec)
    }
}
