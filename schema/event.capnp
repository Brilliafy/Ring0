@0x88d6acbde2e0be96;

struct IpAddr {
    union {
        v4 @0 : UInt32;
        v6 @1 : Data;
    }
}

enum Protocol { tcp @0; udp @1; icmp @2; }
enum Action { pass @0; drop @1; alert @2; }
enum Severity { low @0; med @1; high @2; critical @3; }

struct PacketEvent {
    timestamp @0 : UInt64;
    srcIp @1 : IpAddr; dstIp @2 : IpAddr;
    srcPort @3 : UInt16; dstPort @4 : UInt16;
    protocol @5 : Protocol; pid @6 : UInt32;
    binaryPath @7 : Text; payloadSnippet @8 : Data;
    action @9 : Action;
}
struct ProcessExecEvent {
    timestamp @0 : UInt64;
    pid @1 : UInt32; ppid @2 : UInt32; uid @3 : UInt32;
    binaryPath @4 : Text; commandLine @5 : Text;
}
struct FileAccessEvent {
    timestamp @0 : UInt64;
    pid @1 : UInt32; uid @2 : UInt32;
    binaryPath @3 : Text; filePath @4 : Text;
    flags @5 : UInt32; verdict @6 : Action;
}
struct ConnectEvent {
    timestamp @0 : UInt64;
    pid @1 : UInt32; uid @2 : UInt32;
    binaryPath @3 : Text;
    srcIp @4 : IpAddr; dstIp @5 : IpAddr;
    dstPort @6 : UInt16; protocol @7 : Protocol;
}
struct CorrelationAlert {
    timestamp @0 : UInt64;
    patternId @1 : UInt32;
    patternName @2 : Text;
    mitreTactic @3 : Text;
    mitreTechnique @4 : Text;
    severity @5 : Severity;
    rootPid @6 : UInt32;
    chainEventIds @7 : List(UInt64);
    chainDescription @8 : Text;
}
struct SelfDefenseEvent {
    timestamp @0 : UInt64;
    attackerPid @1 : UInt32;
    attackerBinary @2 : Text;
    targetPath @3 : Text;
    syscall @4 : Text;
    blocked @5 : Bool;
}
struct DnsQueryEvent {
    timestamp @0 : UInt64;
    pid @1 : UInt32;
    domain @2 : Text;
    queryType @3 : UInt16;
    responseIp @4 : Text;
    dgaScore @5 : Float32;
}
struct AlertEvent {
    timestamp @0 : UInt64;
    severity @1 : Severity; ruleId @2 : UInt32;
    signatureName @3 : Text; matchedPattern @4 : Text;
    payloadContext @5 : Data;
}
struct DaemonStatus {
    activeFilters @0 : List(Text);
    cpuUsagePercent @1 : Float32; ramUsageBytes @2 : UInt64;
    eventsPerSec @3 : Float64;
}
struct Ring0Event {
    union {
    packet @0 : PacketEvent;
    alert @1 : AlertEvent;
    status @2 : DaemonStatus;
    processExec @3 : ProcessExecEvent;
    fileAccess @4 : FileAccessEvent;
    connect @5 : ConnectEvent;
    correlation @6 : CorrelationAlert;
    selfDefense @7 : SelfDefenseEvent;
    dns @8 : DnsQueryEvent;
    connectionPrompt @9 : ConnectionPromptEvent;
    }
}

struct ConnectionPromptEvent {
    timestamp @0 : UInt64;
    promptId @1 : UInt64;
    pid @2 : UInt32;
    ppid @3 : UInt32;
    binaryPath @4 : Text;
    parentBinary @5 : Text;
    dstIp @6 : UInt32;
    dstPort @7 : UInt16;
    protocol @8 : UInt8;
    countryCode @9 : Text;
    countryName @10 : Text;
    rdnsName @11 : Text;
    timeoutSecs @12 : UInt32;
}

struct LogQuery {
    startTimestamp @0 : UInt64; endTimestamp @1 : UInt64;
    severityThreshold @2 : UInt8; limit @3 : UInt32;
}
struct AlertRecord {
    timestamp @0 : UInt64; severity @1 : Severity;
    ruleId @2 : UInt32; signatureName @3 : Text;
    matchedPattern @4 : Text;
}
struct QueryResponse {
    alerts @0 : List(AlertRecord); count @1 : UInt32;
}
struct PromptDecisionCommand {
    promptId @0 : UInt64;
    action @1 : Text;
    scope @2 : Text;
}
struct DaemonCommand {
    union {
    blockIp @0 : Text;
    unblockIp @1 : Text;
    killProcess @2 : UInt32;
    reloadFilters @3 : Void;
    shutdown @4 : Void;
    queryLogs @5 : LogQuery;
    reloadRules @6 : Void;
    quarantine @7 : UInt32;
    runRootkitScan @8 : Void;
    syncIntelFeeds @9 : Void;
    submitPromptDecision @10 : PromptDecisionCommand;
    flatpakList @11 : Void;
    powerStatus @12 : Void;
    updateSettings @13 : Text;
    runDoctor @14 : Void;
    }
}