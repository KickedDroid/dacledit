use std::env;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

extern "C" {
    fn modify_dacl(
        ldap_uri: *const c_char,
        ccache_path: *const c_char,
        target_dn: *const c_char,
        new_sd: *const c_char,
    ) -> c_int;
}

pub fn rust_modify_dacl(
    ldap_uri: &str,
    ccache_path: Option<&str>,
    target_dn: &str,
    new_sd: &str,
) -> Result<(), String> {
    let c_ldap_uri = CString::new(ldap_uri).map_err(|e| e.to_string())?;
    //let c_ccache_path = CString::new(ccache_path).map_err(|e| e.to_string())?;
    let c_target_dn = CString::new(target_dn).map_err(|e| e.to_string())?;
    let c_new_sd = CString::new(new_sd).map_err(|e| e.to_string())?;


    let c_ccache_path = match ccache_path {
        Some(path) => CString::new(path).map_err(|e| e.to_string())?,
        None => {
            // Look for KRB5CCNAME in environment variables
            match env::var("KRB5CCNAME") {
                Ok(path) => CString::new(path).map_err(|e| e.to_string())?,
                Err(_) => return Err("KRB5CCNAME not found in environment variables".to_string()),
            }
        }
    };


    let result = unsafe {
        modify_dacl(
            c_ldap_uri.as_ptr(),
            c_ccache_path.as_ptr(),
            c_target_dn.as_ptr(),
            c_new_sd.as_ptr(),
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(format!("[Native.rs] - modify_dacl failed with error code: {}", result))
    }
}