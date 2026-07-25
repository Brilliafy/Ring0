use std::pin::Pin;

use cxx::CxxVector;
use cxx_qt::QVector;

#[cxx_qt::bridge]
pub mod qml_models {
    unsafe extern "C++" {
        include!("ring0-gui/src/bridge/ring0_bridge.h");

        #[namespace = "std"]
        type Vector_T = CxxVector<PacketRecord>;
    }

    #[derive(Debug, Clone)]
    pub struct PacketRecord {
        pub timestamp: String,
        pub src_ip: String,
        pub dst_ip: String,
        pub src_port: u16,
        pub dst_port: u16,
        pub protocol: String,
        pub pid: u32,
        pub action: String,
    }

    #[derive(Debug, Clone)]
    pub struct ProcessRecord {
        pub pid: u32,
        pub ppid: u32,
        pub binary: String,
        pub cmdline: String,
    }

    unsafe extern "Rust" {
        #[qobject]
        type PacketLogModel;

        #[qsignal]
        fn modelReset(self: Pin<&mut PacketLogModel>);

        #[qsignal]
        fn rowsInserted(self: Pin<&mut PacketLogModel>, parent: i32, first: i32, last: i32);

        #[qsignal]
        fn rowsRemoved(self: Pin<&mut PacketLogModel>, parent: i32, first: i32, last: i32);

        #[qinvokable]
        fn appendPackets(self: Pin<&mut PacketLogModel>, packets: Vec<PacketRecord>);

        #[qinvokable]
        fn clearPackets(self: Pin<&mut PacketLogModel>);

        #[qinvokable]
        fn packetCount(self: Pin<&mut PacketLogModel>) -> i32;

        #[qinvokable]
        fn packetAt(self: Pin<&mut PacketLogModel>, index: i32) -> PacketRecord;

        #[qinvokable]
        fn removeOlderThan(self: Pin<&mut PacketLogModel>, max_count: i32);
    }

    unsafe extern "Rust" {
        #[qobject]
        type ProcessListModel;

        #[qsignal]
        fn modelReset(self: Pin<&mut ProcessListModel>);

        #[qsignal]
        fn rowsInserted(self: Pin<&mut ProcessListModel>, parent: i32, first: i32, last: i32);

        #[qinvokable]
        fn appendProcess(self: Pin<&mut ProcessListModel>, proc: ProcessRecord);

        #[qinvokable]
        fn clearProcesses(self: Pin<&mut ProcessListModel>);

        #[qinvokable]
        fn processCount(self: Pin<&mut ProcessListModel>) -> i32;

        #[qinvokable]
        fn processAt(self: Pin<&mut ProcessListModel>, index: i32) -> ProcessRecord;

        #[qinvokable]
        fn removeOlderThan(self: Pin<&mut ProcessListModel>, max_count: i32);
    }
}

use std::collections::VecDeque;

pub struct PacketLogModel {
    packets: VecDeque<qml_models::PacketRecord>,
    max_size: usize,
}

impl Default for PacketLogModel {
    fn default() -> Self {
        Self {
            packets: VecDeque::with_capacity(2048),
            max_size: 5000,
        }
    }
}

impl PacketLogModel {
    pub fn append_packets(self: Pin<&mut Self>, new_packets: Vec<qml_models::PacketRecord>) {
        let this = self.get_mut();
        let count = new_packets.len();
        for p in new_packets {
            if this.packets.len() >= this.max_size {
                this.packets.pop_front();
            }
            this.packets.push_back(p);
        }
    }

    pub fn clear_packets(self: Pin<&mut Self>) {
        let this = self.get_mut();
        let removed = this.packets.len() as i32;
        this.packets.clear();
    }

    pub fn packet_count(self: Pin<&mut Self>) -> i32 {
        self.get_mut().packets.len() as i32
    }

    pub fn packet_at(self: Pin<&mut Self>, index: i32) -> qml_models::PacketRecord {
        let this = self.get_mut();
        if index >= 0 && (index as usize) < this.packets.len() {
            this.packets[index as usize].clone()
        } else {
            qml_models::PacketRecord {
                timestamp: String::new(),
                src_ip: String::new(),
                dst_ip: String::new(),
                src_port: 0,
                dst_port: 0,
                protocol: String::new(),
                pid: 0,
                action: String::new(),
            }
        }
    }

    pub fn remove_older_than(self: Pin<&mut Self>, max_count: i32) {
        let this = self.get_mut();
        while this.packets.len() > max_count as usize {
            this.packets.pop_front();
        }
    }
}

pub struct ProcessListModel {
    processes: VecDeque<qml_models::ProcessRecord>,
    max_size: usize,
}

impl Default for ProcessListModel {
    fn default() -> Self {
        Self {
            processes: VecDeque::with_capacity(1024),
            max_size: 2000,
        }
    }
}

impl ProcessListModel {
    pub fn append_process(self: Pin<&mut Self>, proc: qml_models::ProcessRecord) {
        let this = self.get_mut();
        if this.processes.len() >= this.max_size {
            this.processes.pop_front();
        }
        this.processes.push_back(proc);
    }

    pub fn clear_processes(self: Pin<&mut Self>) {
        self.get_mut().processes.clear();
    }

    pub fn process_count(self: Pin<&mut Self>) -> i32 {
        self.get_mut().processes.len() as i32
    }

    pub fn process_at(self: Pin<&mut Self>, index: i32) -> qml_models::ProcessRecord {
        let this = self.get_mut();
        if index >= 0 && (index as usize) < this.processes.len() {
            this.processes[index as usize].clone()
        } else {
            qml_models::ProcessRecord {
                pid: 0,
                ppid: 0,
                binary: String::new(),
                cmdline: String::new(),
            }
        }
    }

    pub fn remove_older_than(self: Pin<&mut Self>, max_count: i32) {
        let this = self.get_mut();
        while this.processes.len() > max_count as usize {
            this.processes.pop_front();
        }
    }
}
