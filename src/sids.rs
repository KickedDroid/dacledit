use std::collections::HashMap;
use lazy_static::lazy_static;
use bitflags::bitflags;
use uuid::Uuid;


#[derive(Debug, Clone, Copy)]
pub enum RightsGuid {
    WriteMembers,
    ResetPassword,
    DsReplicationGetChanges,
    DsReplicationGetChangesAll,
}

impl RightsGuid {
    pub fn as_uuid(&self) -> Uuid {
        match self {
            RightsGuid::WriteMembers => Uuid::parse_str("bf9679c0-0de6-11d0-a285-00aa003049e2").unwrap(),
            RightsGuid::ResetPassword => Uuid::parse_str("00299570-246d-11d0-a768-00aa006e0529").unwrap(),
            RightsGuid::DsReplicationGetChanges => Uuid::parse_str("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2").unwrap(),
            RightsGuid::DsReplicationGetChangesAll => Uuid::parse_str("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2").unwrap(),
        }
    }
}

lazy_static! {
    pub static ref RIGHTS_GUID_MAP: HashMap<&'static str, RightsGuid> = {
        let mut m = HashMap::new();
        m.insert("WriteMembers", RightsGuid::WriteMembers);
        m.insert("ResetPassword", RightsGuid::ResetPassword);
        m.insert("DS_Replication_Get_Changes", RightsGuid::DsReplicationGetChanges);
        m.insert("DS_Replication_Get_Changes_All", RightsGuid::DsReplicationGetChangesAll);
        m
    };
}

bitflags! {
    pub struct AccessMask: u32 {
        const GENERIC_READ = 0x80000000;
        const GENERIC_WRITE = 0x40000000;
        const GENERIC_EXECUTE = 0x20000000;
        const GENERIC_ALL = 0x10000000;
        const MAXIMUM_ALLOWED = 0x02000000;
        const ACCESS_SYSTEM_SECURITY = 0x01000000;
        const SYNCHRONIZE = 0x00100000;
        const WRITE_OWNER = 0x00080000;
        const WRITE_DACL = 0x00040000;
        const READ_CONTROL = 0x00020000;
        const DELETE = 0x00010000;
        const ALL_EXTENDED_RIGHTS = 0x00000100;
        const LIST_OBJECT = 0x00000080;
        const DELETE_TREE = 0x00000040;
        const WRITE_PROPERTIES = 0x00000020;
        const READ_PROPERTIES = 0x00000010;
        const SELF = 0x00000008;
        const LIST_CHILD_OBJECTS = 0x00000004;
        const DELETE_CHILD = 0x00000002;
        const CREATE_CHILD = 0x00000001;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SimplePermissions {
    FullControl = 0xf01ff,
    Modify = 0x0301bf,
    ReadAndExecute = 0x0200a9,
    ReadAndWrite = 0x02019f,
    Read = 0x20094,
    Write = 0x200bc,
}

lazy_static! {
    pub static ref SIMPLE_PERMISSIONS_MAP: HashMap<&'static str, SimplePermissions> = {
        let mut m = HashMap::new();
        m.insert("FullControl", SimplePermissions::FullControl);
        m.insert("Modify", SimplePermissions::Modify);
        m.insert("ReadAndExecute", SimplePermissions::ReadAndExecute);
        m.insert("ReadAndWrite", SimplePermissions::ReadAndWrite);
        m.insert("Read", SimplePermissions::Read);
        m.insert("Write", SimplePermissions::Write);
        m
    };
}

lazy_static! {
    pub static ref WELL_KNOWN_SIDS: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("S-1-0", "Null Authority");
        m.insert("S-1-0-0", "Nobody");
        m.insert("S-1-1", "World Authority");
        m.insert("S-1-1-0", "Everyone");
        m.insert("S-1-2", "Local Authority");
        m.insert("S-1-2-0", "Local");
        m.insert("S-1-2-1", "Console Logon");
        m.insert("S-1-3", "Creator Authority");
        m.insert("S-1-3-0", "Creator Owner");
        m.insert("S-1-3-1", "Creator Group");
        m.insert("S-1-3-2", "Creator Owner Server");
        m.insert("S-1-3-3", "Creator Group Server");
        m.insert("S-1-3-4", "Owner Rights");
        m.insert("S-1-5-80-0", "All Services");
        m.insert("S-1-4", "Non-unique Authority");
        m.insert("S-1-5", "NT Authority");
        m.insert("S-1-5-1", "Dialup");
        m.insert("S-1-5-2", "Network");
        m.insert("S-1-5-3", "Batch");
        m.insert("S-1-5-4", "Interactive");
        m.insert("S-1-5-6", "Service");
        m.insert("S-1-5-7", "Anonymous");
        m.insert("S-1-5-8", "Proxy");
        m.insert("S-1-5-9", "Enterprise Domain Controllers");
        m.insert("S-1-5-10", "Principal Self");
        m.insert("S-1-5-11", "Authenticated Users");
        m.insert("S-1-5-12", "Restricted Code");
        m.insert("S-1-5-13", "Terminal Server Users");
        m.insert("S-1-5-14", "Remote Interactive Logon");
        m.insert("S-1-5-15", "This Organization");
        m.insert("S-1-5-17", "This Organization");
        m.insert("S-1-5-18", "Local System");
        m.insert("S-1-5-19", "NT Authority");
        m.insert("S-1-5-20", "NT Authority");
        m.insert("S-1-5-32-544", "Administrators");
        m.insert("S-1-5-32-545", "Users");
        m.insert("S-1-5-32-546", "Guests");
        m.insert("S-1-5-32-547", "Power Users");
        m.insert("S-1-5-32-548", "Account Operators");
        m.insert("S-1-5-32-549", "Server Operators");
        m.insert("S-1-5-32-550", "Print Operators");
        m.insert("S-1-5-32-551", "Backup Operators");
        m.insert("S-1-5-32-552", "Replicators");
        m.insert("S-1-5-64-10", "NTLM Authentication");
        m.insert("S-1-5-64-14", "SChannel Authentication");
        m.insert("S-1-5-64-21", "Digest Authority");
        m.insert("S-1-5-80", "NT Service");
        m.insert("S-1-5-83-0", "NT VIRTUAL MACHINE\\Virtual Machines");
        m.insert("S-1-16-0", "Untrusted Mandatory Level");
        m.insert("S-1-16-4096", "Low Mandatory Level");
        m.insert("S-1-16-8192", "Medium Mandatory Level");
        m.insert("S-1-16-8448", "Medium Plus Mandatory Level");
        m.insert("S-1-16-12288", "High Mandatory Level");
        m.insert("S-1-16-16384", "System Mandatory Level");
        m.insert("S-1-16-20480", "Protected Process Mandatory Level");
        m.insert("S-1-16-28672", "Secure Process Mandatory Level");
        m.insert("S-1-5-32-554", "BUILTIN\\Pre-Windows 2000 Compatible Access");
        m.insert("S-1-5-32-555", "BUILTIN\\Remote Desktop Users");
        m.insert("S-1-5-32-557", "BUILTIN\\Incoming Forest Trust Builders");
        m.insert("S-1-5-32-556", "BUILTIN\\Network Configuration Operators");
        m.insert("S-1-5-32-558", "BUILTIN\\Performance Monitor Users");
        m.insert("S-1-5-32-559", "BUILTIN\\Performance Log Users");
        m.insert("S-1-5-32-560", "BUILTIN\\Windows Authorization Access Group");
        m.insert("S-1-5-32-561", "BUILTIN\\Terminal Server License Servers");
        m.insert("S-1-5-32-562", "BUILTIN\\Distributed COM Users");
        m.insert("S-1-5-32-569", "BUILTIN\\Cryptographic Operators");
        m.insert("S-1-5-32-573", "BUILTIN\\Event Log Readers");
        m.insert("S-1-5-32-574", "BUILTIN\\Certificate Service DCOM Access");
        m.insert("S-1-5-32-575", "BUILTIN\\RDS Remote Access Servers");
        m.insert("S-1-5-32-576", "BUILTIN\\RDS Endpoint Servers");
        m.insert("S-1-5-32-577", "BUILTIN\\RDS Management Servers");
        m.insert("S-1-5-32-578", "BUILTIN\\Hyper-V Administrators");
        m.insert("S-1-5-32-579", "BUILTIN\\Access Control Assistance Operators");
        m.insert("S-1-5-32-580", "BUILTIN\\Remote Management Users");
        m
    };
}