//! A file as seen through the MFT: its base record merged with its extension records.

use crate::anomaly::NtfsAnomaly;
use crate::attr::{
    self, AttrListEntry, EaEntry, EaInfo, FileName, Namespace, ObjectId, Reparse, StdInfo,
    VolumeInfo,
};
use crate::fixup::FixupStatus;
use crate::record::attribute::*;
use crate::record::{MftRecord, NonResident, RecordHeader};
use crate::reference::FileRef;

/// Name of the filename index of a directory.
const I30: &str = "$I30";

/// One `$DATA` stream (unnamed = the file content, named = alternate data stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataStream {
    pub name: String,
    pub flags: u16,
    pub attribute_id: u16,
    /// Resident content (the bytes live in the MFT record itself).
    pub resident: Option<Vec<u8>>,
    /// Non-resident header of the segment starting at VCN 0 (holds the sizes).
    pub non_resident: Option<NonResident>,
    /// Every non-resident segment `(starting_vcn, raw run list)`, sorted by VCN.
    pub segments: Vec<(u64, Vec<u8>)>,
}

impl DataStream {
    pub fn is_resident(&self) -> bool {
        self.resident.is_some()
    }

    /// Logical size.
    pub fn size(&self) -> u64 {
        match (&self.resident, &self.non_resident) {
            (Some(v), _) => v.len() as u64,
            (None, Some(nr)) => nr.data_size,
            (None, None) => 0,
        }
    }

    pub fn is_compressed(&self) -> bool {
        self.flags & ATTR_FLAG_COMPRESSED_MASK != 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & ATTR_FLAG_ENCRYPTED != 0
    }

    pub fn is_sparse(&self) -> bool {
        self.flags & ATTR_FLAG_SPARSE != 0
    }
}

/// State of the `$ATTRIBUTE_LIST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrListState {
    Resident(Vec<AttrListEntry>),
    /// Stored in clusters: not readable from a loose `$MFT` (extensions are found by their
    /// base reference instead).
    NonResident,
}

impl AttrListState {
    pub fn name(&self) -> &'static str {
        match self {
            AttrListState::Resident(_) => "resident",
            AttrListState::NonResident => "non_resident",
        }
    }
}

/// A `$LOGGED_UTILITY_STREAM` (`$EFS`, `$TXF_DATA`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedStream {
    pub name: String,
    pub size: u64,
}

/// A file (or directory) reconstructed from its MFT record(s).
#[derive(Debug, Clone)]
pub struct MftEntry {
    pub reference: FileRef,
    pub header: RecordHeader,
    pub fixup: FixupStatus,
    pub std_info: Option<StdInfo>,
    /// Every `$FILE_NAME`, in record order (hard links and 8.3 names included).
    pub names: Vec<FileName>,
    pub streams: Vec<DataStream>,
    pub object_id: Option<ObjectId>,
    pub reparse: Option<Reparse>,
    pub ea_info: Option<EaInfo>,
    pub eas: Vec<EaEntry>,
    pub logged_streams: Vec<LoggedStream>,
    pub attribute_list: Option<AttrListState>,
    pub volume_name: Option<String>,
    pub volume_info: Option<VolumeInfo>,
    /// Resident `$INDEX_ROOT:$I30` value (directories).
    pub index_root: Option<Vec<u8>>,
    /// Non-resident `$INDEX_ALLOCATION:$I30` header (directories).
    pub index_allocation: Option<NonResident>,
    pub has_security_descriptor: bool,
    /// Owner SID from a resident `$SECURITY_DESCRIPTOR` (NT4-style per-file descriptor, also
    /// written by ntfs-3g). Windows 2000+ files use `$SI.security_id` + `$Secure:$SDS` instead.
    pub descriptor_owner: Option<String>,
    /// Every attribute type present, sorted, unique.
    pub attribute_types: Vec<u32>,
    /// Extension records merged into this entry.
    pub extensions: Vec<FileRef>,
    /// Slack of the base record.
    pub slack: Vec<u8>,
    /// Offset of [`Self::slack`] inside the base record.
    pub slack_offset: usize,
    pub anomalies: Vec<NtfsAnomaly>,
}

impl MftEntry {
    /// Merges a base record with its extension records.
    pub fn from_records(base: MftRecord, extensions: Vec<MftRecord>) -> Self {
        let mut e = MftEntry {
            reference: base.reference(),
            header: base.header.clone(),
            fixup: base.fixup,
            std_info: None,
            names: Vec::new(),
            streams: Vec::new(),
            object_id: None,
            reparse: None,
            ea_info: None,
            eas: Vec::new(),
            logged_streams: Vec::new(),
            attribute_list: None,
            volume_name: None,
            volume_info: None,
            index_root: None,
            index_allocation: None,
            has_security_descriptor: false,
            descriptor_owner: None,
            attribute_types: Vec::new(),
            extensions: extensions.iter().map(|r| r.reference()).collect(),
            slack: base.slack_bytes().to_vec(),
            slack_offset: base.slack.start,
            anomalies: base.anomalies.clone(),
        };
        e.absorb(&base);
        for ext in &extensions {
            e.anomalies.extend(ext.anomalies.iter().cloned());
            e.absorb(ext);
        }
        for s in &mut e.streams {
            s.segments.sort_by_key(|(vcn, _)| *vcn);
        }
        e.attribute_types.sort_unstable();
        e.attribute_types.dedup();
        e
    }

    fn absorb(&mut self, rec: &MftRecord) {
        for a in &rec.attributes {
            self.attribute_types.push(a.type_code);
            let malformed = |reason| NtfsAnomaly::AttributeMalformed {
                type_code: a.type_code,
                reason,
            };
            match (a.type_code, &a.body) {
                (ATTR_STANDARD_INFORMATION, AttrBody::Resident { value, .. })
                    if self.std_info.is_none() =>
                {
                    match StdInfo::parse(value) {
                        Ok(v) => self.std_info = Some(v),
                        Err(r) => self.anomalies.push(malformed(r)),
                    }
                }
                (ATTR_FILE_NAME, AttrBody::Resident { value, .. }) => {
                    match FileName::parse(value) {
                        Ok(v) => self.names.push(v),
                        Err(r) => self.anomalies.push(malformed(r)),
                    }
                }
                (ATTR_DATA, body) => self.add_data(a, body),
                (ATTR_OBJECT_ID, AttrBody::Resident { value, .. }) => {
                    match ObjectId::parse(value) {
                        Ok(v) => self.object_id = Some(v),
                        Err(r) => self.anomalies.push(malformed(r)),
                    }
                }
                (ATTR_REPARSE_POINT, AttrBody::Resident { value, .. }) => {
                    match Reparse::parse(value) {
                        Ok(v) => self.reparse = Some(v),
                        Err(r) => self.anomalies.push(malformed(r)),
                    }
                }
                (ATTR_EA_INFORMATION, AttrBody::Resident { value, .. }) => {
                    match EaInfo::parse(value) {
                        Ok(v) => self.ea_info = Some(v),
                        Err(r) => self.anomalies.push(malformed(r)),
                    }
                }
                (ATTR_EA, AttrBody::Resident { value, .. }) => {
                    if let Err(r) = attr::ea::parse_entries(value, &mut self.eas) {
                        self.anomalies.push(malformed(r));
                    }
                }
                (ATTR_LOGGED_UTILITY_STREAM, _) => self.logged_streams.push(LoggedStream {
                    name: a.name.clone(),
                    size: a.data_size(),
                }),
                (ATTR_ATTRIBUTE_LIST, AttrBody::Resident { value, .. }) => {
                    let mut list = Vec::new();
                    if let Err(r) = attr::attr_list::parse(value, &mut list) {
                        self.anomalies.push(malformed(r));
                    }
                    self.attribute_list = Some(AttrListState::Resident(list));
                }
                (ATTR_ATTRIBUTE_LIST, AttrBody::NonResident(_)) => {
                    self.attribute_list = Some(AttrListState::NonResident);
                }
                (ATTR_VOLUME_NAME, AttrBody::Resident { value, .. }) => {
                    match attr::utf16_at(value, 0, value.len() / 2) {
                        Ok(n) => self.volume_name = Some(n),
                        Err(r) => self.anomalies.push(malformed(r)),
                    }
                }
                (ATTR_VOLUME_INFORMATION, AttrBody::Resident { value, .. }) => {
                    match VolumeInfo::parse(value) {
                        Ok(v) => self.volume_info = Some(v),
                        Err(r) => self.anomalies.push(malformed(r)),
                    }
                }
                (ATTR_INDEX_ROOT, AttrBody::Resident { value, .. }) if a.name == I30 => {
                    self.index_root = Some(value.clone());
                }
                (ATTR_INDEX_ALLOCATION, AttrBody::NonResident(nr)) if a.name == I30 => {
                    if nr.starting_vcn == 0 || self.index_allocation.is_none() {
                        self.index_allocation = Some(nr.clone());
                    }
                }
                (ATTR_SECURITY_DESCRIPTOR, body) => {
                    self.has_security_descriptor = true;
                    if let AttrBody::Resident { value, .. } = body {
                        self.descriptor_owner = crate::secure::descriptor_owner(value);
                    }
                }
                _ => {}
            }
        }
    }

    fn add_data(&mut self, a: &Attribute, body: &AttrBody) {
        let idx = match self.streams.iter().position(|s| s.name == a.name) {
            Some(i) => i,
            None => {
                self.streams.push(DataStream {
                    name: a.name.clone(),
                    flags: a.flags,
                    attribute_id: a.id,
                    resident: None,
                    non_resident: None,
                    segments: Vec::new(),
                });
                self.streams.len() - 1
            }
        };
        let s = &mut self.streams[idx];
        match body {
            AttrBody::Resident { value, .. } => s.resident = Some(value.clone()),
            AttrBody::NonResident(nr) => {
                if nr.starting_vcn == 0 {
                    s.flags = a.flags;
                    s.attribute_id = a.id;
                    s.non_resident = Some(nr.clone());
                }
                s.segments.push((nr.starting_vcn, nr.runlist.clone()));
            }
        }
    }

    pub fn in_use(&self) -> bool {
        self.header.in_use()
    }

    pub fn is_directory(&self) -> bool {
        self.header.is_directory()
    }

    /// The preferred long name (Win32+DOS, Win32, POSIX, then DOS).
    pub fn primary_name(&self) -> Option<&FileName> {
        self.names.iter().min_by_key(|n| n.namespace.rank())
    }

    /// The 8.3 name, when the file has a separate DOS-namespace `$FILE_NAME`.
    pub fn short_name(&self) -> Option<&FileName> {
        self.names.iter().find(|n| n.namespace == Namespace::Dos)
    }

    /// Distinct long names (hard links); DOS-only duplicates are dropped.
    pub fn link_names(&self) -> Vec<&FileName> {
        let mut out: Vec<&FileName> = self
            .names
            .iter()
            .filter(|n| n.namespace != Namespace::Dos)
            .collect();
        if out.is_empty() {
            out = self.names.iter().collect();
        }
        out
    }

    /// The unnamed `$DATA` stream (file content).
    pub fn data(&self) -> Option<&DataStream> {
        self.streams.iter().find(|s| s.name.is_empty())
    }

    /// Named `$DATA` streams (alternate data streams).
    pub fn alternate_streams(&self) -> impl Iterator<Item = &DataStream> {
        self.streams.iter().filter(|s| !s.name.is_empty())
    }

    /// Resident content of a stream (`""` = unnamed), if it is resident.
    pub fn resident_data(&self, stream: &str) -> Option<&[u8]> {
        self.streams
            .iter()
            .find(|s| s.name == stream)?
            .resident
            .as_deref()
    }
}
