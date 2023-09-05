mod iter;
mod prefetch;

use crate::iter::MsgIter;
use crate::prefetch::PrefetchResult;
use bgpkit_broker::BgpkitBroker;
use bgpkit_parser::models::Bgp4Mp::*;
use bgpkit_parser::models::MrtMessage::*;
use bgpkit_parser::models::TableDumpV2Message::*;
use bgpkit_parser::models::{
    AttrType, Attributes, Bgp4MpMessage, BgpMessage, MrtMessage, RibAfiEntries, RibGenericEntries,
    TableDumpMessage as TableDump,
};
use chrono::{Days, Utc};
use rayon::prelude::*;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Instant;

const OUTPUT_FILE: &str = "output.txt";

const MAX_PREFETCH_BUFFER_SIZE: usize = 1 << 30; // 1GB
const PREFETCH_BUFFER_SPACE: usize = 32 << 30; // 32GB (my system has 64GB, but it only uses ~6GB)

// Counters to assist with printing progress
static TOTAL_ITEMS: AtomicUsize = AtomicUsize::new(0);
static COMPLETED: AtomicUsize = AtomicUsize::new(0);

fn main() {
    let start_time = Instant::now();
    let yesterdays_broker_items = BgpkitBroker::new()
        .page_size(1000)
        .ts_start((Utc::now() - Days::new(1)).timestamp())
        .query()
        .unwrap();

    println!(
        "Fetched {} item from bgpkit broker in {:?}",
        yesterdays_broker_items.len(),
        start_time.elapsed()
    );

    let updates = yesterdays_broker_items
        .iter()
        .filter(|x| x.data_type == "update")
        .cloned()
        .collect::<Vec<_>>();
    let rib_dumps = yesterdays_broker_items
        .iter()
        .filter(|x| x.data_type == "rib")
        .cloned()
        .collect::<Vec<_>>();

    let mut output_file = BufWriter::new(File::create(OUTPUT_FILE).unwrap());

    TOTAL_ITEMS.store(updates.len(), SeqCst);
    let updates_start_time = Instant::now();
    let update_counts = prefetch::prefetch_iter(updates, 32, 32)
        .par_bridge()
        .map(map_broker_item_to_counts)
        .reduce(AttributeCounts::default, AttributeCounts::reduce);

    println!("\nBGP update attribute counts:");
    println!("{}", update_counts);
    println!(
        "\nFinished reading updates in {:?}\n",
        updates_start_time.elapsed()
    );

    writeln!(&mut output_file, "BGP update attribute counts:").unwrap();
    writeln!(&mut output_file, "{}", update_counts).unwrap();
    output_file.flush().unwrap();

    TOTAL_ITEMS.store(rib_dumps.len(), SeqCst);
    COMPLETED.store(0, SeqCst);
    let rib_dumps_start_time = Instant::now();
    let rib_counts = prefetch::prefetch_iter(rib_dumps, 32, 32)
        .par_bridge()
        .map(map_broker_item_to_counts)
        .reduce(AttributeCounts::default, AttributeCounts::reduce);

    println!("\nBGP rib dump attribute counts:");
    println!("{}", rib_counts);
    println!(
        "\nFinished reading rib dumps in {:?}\n",
        rib_dumps_start_time.elapsed()
    );

    writeln!(&mut output_file, "\nBGP rib dump attribute counts:").unwrap();
    writeln!(&mut output_file, "{}", rib_counts).unwrap();

    println!("Finished in {:?}", start_time.elapsed());
}

fn map_broker_item_to_counts(item: PrefetchResult) -> AttributeCounts {
    let start_time = Instant::now();
    let mut attribute_counts = AttributeCounts::default();

    for record in MsgIter::new(item.reader) {
        match record {
            Ok(x) => attribute_counts.count_record(x.message),
            Err(err) => println!("Error in {}: {}", item.url, err),
        }
    }

    println!(
        "[{}/{}] Finished {} in {:?}",
        COMPLETED.fetch_add(1, SeqCst) + 1,
        TOTAL_ITEMS.load(SeqCst),
        item.url,
        start_time.elapsed()
    );
    attribute_counts
}

type AttrTypeList = SmallVec<[AttrType; 6]>;

#[derive(Clone)]
struct AttributeCounts {
    map: HashMap<AttrTypeList, u64>,
    totals: HashMap<AttrType, u64>,
}

impl Default for AttributeCounts {
    fn default() -> Self {
        use AttrType::*;
        let all_attributes = [
            ORIGIN,
            AS_PATH,
            NEXT_HOP,
            MULTI_EXIT_DISCRIMINATOR,
            LOCAL_PREFERENCE,
            ATOMIC_AGGREGATE,
            AGGREGATOR,
            COMMUNITIES,
            ORIGINATOR_ID,
            CLUSTER_LIST,
            CLUSTER_ID,
            MP_REACHABLE_NLRI,
            MP_UNREACHABLE_NLRI,
            EXTENDED_COMMUNITIES,
            AS4_PATH,
            AS4_AGGREGATOR,
            PMSI_TUNNEL,
            TUNNEL_ENCAPSULATION,
            TRAFFIC_ENGINEERING,
            IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES,
            AIGP,
            PE_DISTINGUISHER_LABELS,
            BGP_LS_ATTRIBUTE,
            LARGE_COMMUNITIES,
            BGPSEC_PATH,
            ONLY_TO_CUSTOMER,
            SFP_ATTRIBUTE,
            BFD_DISCRIMINATOR,
            BGP_PREFIX_SID,
            ATTR_SET,
            DEVELOPMENT,
        ];

        let mut totals = HashMap::new();
        for attr in all_attributes {
            totals.insert(attr, 0);
        }

        AttributeCounts {
            map: HashMap::new(),
            totals,
        }
    }
}

impl AttributeCounts {
    fn count_record(&mut self, record: MrtMessage) {
        match record {
            TableDumpMessage(TableDump { attributes, .. }) => self.add_to_count(attributes),
            TableDumpV2Message(PeerIndexTable(_)) => {}
            TableDumpV2Message(
                RibAfi(RibAfiEntries { rib_entries, .. })
                | RibGeneric(RibGenericEntries { rib_entries, .. }),
            ) => rib_entries
                .into_iter()
                .for_each(|entry| self.add_to_count(entry.attributes)),
            Bgp4Mp(StateChange(_)) => {}
            Bgp4Mp(Message(Bgp4MpMessage { bgp_message, .. })) => match bgp_message {
                BgpMessage::Update(update) => self.add_to_count(update.attributes),
                BgpMessage::Open(_) | BgpMessage::Notification(_) | BgpMessage::KeepAlive => {}
            },
        }
    }

    fn add_to_count(&mut self, attributes: Attributes) {
        let mut observed_types =
            SmallVec::from_iter((&*attributes).into_iter().map(|x| x.attr_type));
        observed_types.sort_unstable_by_key(|x| u8::from(*x));

        for x in &observed_types {
            *self.totals.entry(*x).or_default() += 1;
        }

        let count = self.map.entry(observed_types).or_default();
        *count += 1;
    }

    fn reduce(mut self, other: Self) -> Self {
        for (key, value) in other.map {
            let entry = self.map.entry(key).or_default();
            *entry += value;
        }
        for (key, value) in other.totals {
            let entry = self.totals.entry(key).or_default();
            *entry += value;
        }

        self
    }
}

impl Display for AttributeCounts {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut items = self.map.iter().collect::<Vec<_>>();
        items.sort_unstable_by_key(|(_, x)| *x);

        writeln!(f, "Attribute Group Counts")?;
        writeln!(f, "COUNT         PERCENT NAME")?;
        let total_items: u64 = self.map.values().copied().sum();
        for (attrs, count) in items {
            let percent = 100.0 * (*count as f64) / (total_items as f64);
            writeln!(f, "{: <10}{: >10.05}% {:?}", count, percent, attrs)?;
        }

        writeln!(f, "\nTotal Attribute Counts")?;
        writeln!(f, "COUNT         PERCENT NAME")?;
        let mut items = self.totals.iter().collect::<Vec<_>>();
        items.sort_unstable_by_key(|(_, x)| *x);
        for (attr, count) in items {
            let percent = 100.0 * (*count as f64) / (total_items as f64);
            writeln!(f, "{: <10}{: >10.05}% {:?}", count, percent, attr)?;
        }

        Ok(())
    }
}
