use std::ffi::CString;
use std::os::raw::c_int;
use clap::Parser;

mod native;
use native::rust_modify_dacl;

#[link(name = "dacledit")]
extern "C" {
    fn modify_dacl(ldap_uri: *const i8, ccache_path: *const i8,
                   target_dn: *const i8, new_sd: *const i8) -> c_int;
}

#[derive(Parser)]
#[command(name = "DACLEdit")]
#[command(about = "Modify DACL for Active Directory objects", long_about = None)]
struct Cli {
    /// Action to perform (e.g., 'write')
    #[arg(long)]
    action: String,

    /// Rights to set (e.g., 'FullControl')
    #[arg(long)]
    rights: String,

    /// Enable inheritance
    #[arg(long)]
    inheritance: bool,

    /// Principal to set rights for
    #[arg(long)]
    principal: String,

    /// Target Distinguished Name
    #[arg(long = "target-dn")]
    target_dn: String,

    /// LDAP URI
    #[arg(long, default_value = "ldap://dc01.infiltrator.htb")]
    ldap_uri: String,

    /// Kerberos ccache path
    #[arg(long, default_value = "/tmp/krb5cc_1000")]
    ccache_path: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Generate the security descriptor
    let inheritance_flag = if cli.inheritance { "CI" } else { "" };
    let new_sd = format!("D:(A;;{};;;{}){}", cli.rights, cli.principal, inheritance_flag);

    let result = rust_modify_dacl(
        &cli.ldap_uri,
        &cli.ccache_path,
        &cli.target_dn,
        &new_sd,
    );

    match result {
        Ok(()) => {
            println!("DACL modification successful");
            Ok(())
        },
        Err(e) => {
            eprintln!("DACL modification failed: {}", e);
            Err(e.into())
        },
    }
}