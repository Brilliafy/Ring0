use std::collections::HashMap;
use std::pin::Pin;

use cxx_qt::QVector;

#[cxx_qt::bridge]
pub mod qml_topology {
    unsafe extern "C++ {
        include!("ring0-gui/src/bridge/ring0_bridge.h");
    }

    #[derive(Debug, Clone)]
    pub struct TopologyNode {
        pub node_id: u32,
        pub node_type: String,
        pub label: String,
        pub ip: String,
        pub port: u16,
        pub pid: u32,
        pub threat_level: u8,
        pub bytes_per_sec: u64,
        pub country_code: String,
    }

    #[derive(Debug, Clone)]
    pub struct TopologyEdge {
        pub source_id: u32,
        pub target_id: u32,
        pub bytes_per_sec: u64,
        pub protocol: String,
        pub is_active: bool,
    }

    unsafe extern "Rust" {
        #[qobject]
        type TopologyModel;

        #[qinvokable]
        fn setNodes(self: Pin<&mut TopologyModel>, nodes: Vec<TopologyNode>);

        #[qinvokable]
        fn addEdge(self: Pin<&mut TopologyModel>, edge: TopologyEdge);

        #[qinvokable]
        fn nodeCount(self: Pin<&mut TopologyModel>) -> i32;

        #[qinvokable]
        fn edgeCount(self: Pin<&mut TopologyModel>) -> i32;

        #[qinvokable]
        fn clearGraph(self: Pin<&mut TopologyModel>);
    }
}

use std::collections::VecDeque;

pub struct TopologyModel {
    nodes: VecDeque<qml_topology::TopologyNode>,
    edges: VecDeque<qml_topology::TopologyEdge>,
    max_nodes: usize,
    max_edges: usize,
}

impl Default for TopologyModel {
    fn default() -> Self {
        Self {
            nodes: VecDeque::with_capacity(200),
            edges: VecDeque::with_capacity(1000),
            max_nodes: 200,
            max_edges: 1000,
        }
    }
}

impl TopologyModel {
    pub fn set_nodes(self: Pin<&mut Self>, new_nodes: Vec<qml_topology::TopologyNode>) {
        let this = self.get_mut();
        this.nodes.clear();
        for n in new_nodes {
            if this.nodes.len() >= this.max_nodes { break; }
            this.nodes.push_back(n);
        }
    }

    pub fn add_edge(self: Pin<&mut Self>, edge: qml_topology::TopologyEdge) {
        let this = self.get_mut();
        if this.edges.len() >= this.max_edges {
            this.edges.pop_front();
        }
        this.edges.push_back(edge);
    }

    pub fn node_count(self: Pin<&mut Self>) -> i32 {
        self.get_mut().nodes.len() as i32
    }

    pub fn edge_count(self: Pin<&mut Self>) -> i32 {
        self.get_mut().edges.len() as i32
    }

    pub fn clear_graph(self: Pin<&mut Self>) {
        let this = self.get_mut();
        this.nodes.clear();
        this.edges.clear();
    }
}
