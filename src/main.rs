use std::ffi::CString;
use std::os::raw::c_int;

use native::rust_modify_dacl;
mod native;
#[link(name = "dacledit")]
extern "C" {
    fn modify_dacl(ldap_uri: *const i8, ccache_path: *const i8,
                   target_dn: *const i8, new_sd: *const i8) -> c_int;
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = rust_modify_dacl(
        "ldap://dc01.example.com",
        "/tmp/krb5cc_1000",
        "CN=User,DC=example,DC=com",
        "D:PAI(A;;FA;;;S-1-5-21-...)",
    );

    match result {
        Ok(()) => {println!("DACL modification successful");
            Ok(())
        },
        Err(e) => {eprintln!("DACL modification failed: {}", e);
        Err(e.into())
    },
    }
}