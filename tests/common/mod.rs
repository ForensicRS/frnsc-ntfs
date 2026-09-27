//! Shared pipeline harness: run factories through `TriagePipeline` with a collecting sink.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use forensic_rs::prelude::*;
use forensic_rs::provenance::{Acquisition, ProvenanceStore};

#[derive(Clone, Default)]
pub struct Collector {
    pub records: Arc<Mutex<Vec<ForensicData>>>,
    pub findings: Arc<Mutex<Vec<Finding>>>,
}

impl TriageSink for Collector {
    fn name(&self) -> &str {
        "collector"
    }
    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        self.records.lock().unwrap().push(data.clone());
        Ok(())
    }
    fn on_finding(&mut self, finding: &Finding) -> ForensicResult<()> {
        self.findings.lock().unwrap().push(finding.clone());
        Ok(())
    }
}

pub struct Run {
    pub records: Vec<ForensicData>,
    pub findings: Vec<Finding>,
    pub result: PipelineResult,
    pub store: ProvenanceStore,
}

pub fn run(fs: Arc<dyn FileSystem>, parsers: Vec<Arc<dyn ArtifactParserFactory>>) -> Run {
    let context = TriageContext::new("TEST-HOST", "default");
    let store = context.provenance_store();
    let collector = Collector::default();
    let mut builder = TriagePipeline::builder()
        .context(context)
        .sink(Box::new(collector.clone()))
        .on_parser_error(ErrorAction::Continue);
    for p in parsers {
        builder = builder.parser(p);
    }
    let mut pipeline = builder.build().unwrap();
    let sources = TriageSources::builder()
        .vfs(fs)
        .acquisition(Acquisition::ImageRead)
        .build();
    let result = pipeline.run(&sources).unwrap();
    let records = collector.records.lock().unwrap().clone();
    let findings = collector.findings.lock().unwrap().clone();
    Run {
        records,
        findings,
        result,
        store,
    }
}

pub fn by_field<'a>(records: &'a [ForensicData], key: &str, value: &str) -> Vec<&'a ForensicData> {
    records
        .iter()
        .filter(|d| d.field_as_str(key) == Some(value))
        .collect()
}

pub fn one<'a>(records: &'a [ForensicData], key: &str, value: &str) -> &'a ForensicData {
    let v = by_field(records, key, value);
    assert_eq!(
        v.len(),
        1,
        "expected one record with {key}={value}, got {}",
        v.len()
    );
    v[0]
}
