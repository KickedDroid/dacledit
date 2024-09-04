use std::ffi::CString;
use std::os::raw::c_int;
use clap::{builder::NonEmptyStringValueParser, Parser};

mod native;
use native::rust_modify_dacl;

mod sids;
use sids::{AccessMask, RIGHTS_GUID_MAP, SIMPLE_PERMISSIONS_MAP, WELL_KNOWN_SIDS};

#[link(name = "dacledit")]
extern "C" {
    fn modify_dacl(ldap_uri: *const i8, ccache_path: *const i8,
                   target_dn: *const i8, new_sd: *const i8) -> c_int;
}

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
    access_mask: Option<String>,

    #[arg(long)]
    rights: Option<String>,

    /// Extended right (if applicable)
    #[arg(long)]
    extended_right: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if let Some(name) = WELL_KNOWN_SIDS.get(&cli.principal.as_str()) {
        println!("Principal {} is a well-known SID: {}", cli.principal, name);
    }

    let inheritance_flag = if cli.inheritance { "CI" } else { "" };
    let new_sd = if let Some(extended_right) = cli.extended_right {
        if let Some(rights_guid) = RIGHTS_GUID_MAP.get(extended_right.as_str()) {
            format!("D:(A;;CC;;;{}){}:{}", cli.principal, inheritance_flag, rights_guid.as_uuid())
        } else {
            return Err(format!("Unknown extended right: {}", extended_right).into());
        }
    } else if let Some(access_mask_str) = cli.access_mask {
        let mut access_mask = AccessMask::empty();
        for right in access_mask_str.split(',') {
            access_mask |= match right.trim() {
                "GenericRead" => AccessMask::GENERIC_READ,
                "GenericWrite" => AccessMask::GENERIC_WRITE,
                "GenericExecute" => AccessMask::GENERIC_EXECUTE,
                "GenericAll" => AccessMask::GENERIC_ALL,
                
                _ => return Err(format!("Unknown access right: {}", right).into()),
            };
        }
        format!("D:(A;;{};;;{}){}", access_mask.bits(), cli.principal, inheritance_flag)
    } else if let Some(simple_permission) = cli.rights {
        if let Some(permission) = SIMPLE_PERMISSIONS_MAP.get(simple_permission.as_str()) {
            format!("D:(A;;{};;;{}){}", *permission as u32, cli.principal, inheritance_flag)
        } else {
            return Err(format!("Unknown simple permission: {}", simple_permission).into());
        }
    } else {
        return Err("No permission specified. Use --access-mask, --simple-permission, or --extended-right".into());
    };

    let sd = &new_sd.clone().to_string();
    println!("{}", sd);

    let result = rust_modify_dacl(
        &cli.ldap_uri,
        cli.ccache_path.as_deref(),
        &cli.target_dn,
        &new_sd,
    );

    match result {
        Ok(()) => {
            println!("DACL modification successful!");
            Ok(())
        },
        Err(e) => {
            eprintln!("{}", e);
            Err(e.into())
        },
    }
}