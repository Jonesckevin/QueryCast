/**
 * field-maps.js
 * Field name mapping tables for Sigma → SIEM backend conversion.
 * Based on official pySigma processing pipeline field mappings.
 *
 * Backend keys: splunk | elastic | kql_sec | kql_dev | cb | vql | s1 | xql | udm
 *   splunk    → Splunk SPL (Windows Event Log / Sysmon CIM)
 *   elastic   → Elasticsearch ECS (Elastic Common Schema, also used by EQL & Graylog)
 *   kql_sec   → Microsoft Sentinel KQL (SecurityEvent table)
 *   kql_dev   → Microsoft Defender for Endpoint KQL (DeviceEvents tables)
 *   cb        → Carbon Black EDR / CB Cloud (Lucene-style)
 *   vql       → Velociraptor VQL (raw event data field names)
 *   s1        → SentinelOne Deep Visibility query field names
 *   xql       → Palo Alto Cortex XDR XQL field names
 *   udm       → Google Chronicle UDM Search field names
 */
'use strict';

const FieldMaps = (() => {

    // ── Windows: Process Creation ────────────────────────────────────────
    // Sysmon Event ID 1 / Windows Security Event 4688
    const PROCESS_CREATION = {
        'EventID':              { splunk: 'EventCode',         elastic: 'event.code',                       kql_sec: 'EventID',          kql_dev: null,                               cb: null,           vql: 'EventID',          s1: 'EventId',               xql: null,                                   udm: null },
        'Image':                { splunk: 'Image',             elastic: 'process.executable',               kql_sec: 'NewProcessName',   kql_dev: 'FolderPath',                       cb: 'process_name', vql: 'Image',            s1: 'SrcProcImagePath',      xql: 'actor_process_image_path',             udm: 'principal.process.file.full_path' },
        'CommandLine':          { splunk: 'CommandLine',       elastic: 'process.command_line',             kql_sec: 'CommandLine',      kql_dev: 'ProcessCommandLine',               cb: 'cmdline',      vql: 'CommandLine',      s1: 'SrcProcCmdLine',        xql: 'actor_process_command_line',           udm: 'principal.process.command_line' },
        'ParentImage':          { splunk: 'ParentImage',       elastic: 'process.parent.executable',        kql_sec: 'ParentProcessName', kql_dev: 'InitiatingProcessFolderPath',     cb: 'parent_name',  vql: 'ParentImage',      s1: 'SrcProcParentName',     xql: 'causality_actor_process_image_path',   udm: 'principal.process.parent_process.file.full_path' },
        'ParentCommandLine':    { splunk: 'ParentCommandLine', elastic: 'process.parent.command_line',      kql_sec: 'ParentCommandLine', kql_dev: 'InitiatingProcessCommandLine',    cb: null,           vql: 'ParentCommandLine', s1: 'SrcProcParentCmdLine',  xql: 'causality_actor_process_command_line', udm: null },
        'ParentProcessId':      { splunk: 'ParentProcessId',   elastic: 'process.parent.pid',               kql_sec: 'ProcessId',        kql_dev: 'InitiatingProcessId',              cb: null,           vql: 'Ppid',             s1: 'SrcProcParentPid',      xql: 'causality_actor_process_os_pid',       udm: null },
        'ProcessId':            { splunk: 'ProcessId',         elastic: 'process.pid',                      kql_sec: 'NewProcessId',     kql_dev: 'ProcessId',                        cb: null,           vql: 'Pid',              s1: 'SrcProcPid',            xql: 'actor_process_os_pid',                 udm: 'principal.process.pid' },
        'User':                 { splunk: 'User',              elastic: 'user.name',                        kql_sec: 'SubjectUserName',  kql_dev: 'AccountName',                      cb: 'username',     vql: 'User',             s1: 'SrcProcUser',           xql: 'actor_primary_username',               udm: 'principal.user.userid' },
        'IntegrityLevel':       { splunk: 'IntegrityLevel',    elastic: 'process.pe.description',           kql_sec: null,               kql_dev: 'ProcessIntegrityLevel',            cb: null,           vql: 'IntegrityLevel',   s1: 'SrcProcIntegrityLevel', xql: null,                                   udm: null },
        'OriginalFileName':     { splunk: 'OriginalFileName',  elastic: 'process.pe.original_file_name',    kql_sec: null,               kql_dev: 'ProcessVersionInfoOriginalFileName', cb: null,          vql: 'OriginalFileName', s1: null,                    xql: null,                                   udm: null },
        'Product':              { splunk: 'Product',           elastic: 'process.pe.product',               kql_sec: null,               kql_dev: 'ProcessVersionInfoProductName',     cb: null,           vql: 'Product',          s1: null,                    xql: null,                                   udm: null },
        'Description':          { splunk: 'Description',       elastic: 'process.pe.description',           kql_sec: null,               kql_dev: 'ProcessVersionInfoFileDescription', cb: null,           vql: 'Description',      s1: null,                    xql: null,                                   udm: null },
        'Company':              { splunk: 'Company',           elastic: 'process.pe.company',               kql_sec: null,               kql_dev: 'ProcessVersionInfoCompanyName',     cb: null,           vql: 'Company',          s1: null,                    xql: null,                                   udm: null },
        'Hashes':               { splunk: 'Hashes',            elastic: 'process.hash',                     kql_sec: null,               kql_dev: 'SHA256',                           cb: 'process_hash', vql: 'Hashes',           s1: null,                    xql: null,                                   udm: null },
        'md5':                  { splunk: 'md5',               elastic: 'process.hash.md5',                 kql_sec: null,               kql_dev: 'MD5',                              cb: 'md5',          vql: 'MD5',              s1: 'Md5',                   xql: 'actor_process_file_hash_md5',          udm: 'principal.process.file.md5' },
        'sha256':               { splunk: 'sha256',            elastic: 'process.hash.sha256',              kql_sec: null,               kql_dev: 'SHA256',                           cb: 'sha256',       vql: 'SHA256',           s1: 'Sha256',                xql: 'actor_process_file_hash_sha256',       udm: 'principal.process.file.sha256' },
        'ComputerName':         { splunk: 'ComputerName',      elastic: 'host.name',                        kql_sec: 'Computer',         kql_dev: 'DeviceName',                       cb: 'hostname',     vql: 'Computer',         s1: 'EndpointName',          xql: 'agent_hostname',                       udm: 'principal.hostname' },
        'CurrentDirectory':     { splunk: 'CurrentDirectory',  elastic: 'process.working_directory',        kql_sec: null,               kql_dev: 'ProcessTokenElevationType',        cb: null,           vql: 'CurrentDirectory', s1: null,                    xql: null,                                   udm: null },
        'LogonId':              { splunk: 'LogonId',           elastic: 'winlog.event_data.LogonId',        kql_sec: 'SubjectLogonId',   kql_dev: 'LogonId',                          cb: null,           vql: 'LogonId',          s1: null,                    xql: null,                                   udm: null },
    };

    // ── Windows: Network Connection ──────────────────────────────────────
    // Sysmon Event ID 3
    const NETWORK_CONNECTION = {
        'EventID':              { splunk: 'EventCode',    elastic: 'event.code',           kql_sec: 'EventID',  kql_dev: null,                              cb: null,             vql: 'EventID',          s1: 'EventId',        xql: null,                    udm: null },
        'Image':                { splunk: 'Image',        elastic: 'process.executable',   kql_sec: null,       kql_dev: 'InitiatingProcessFolderPath',     cb: 'process_name',   vql: 'Image',            s1: 'SrcProcImagePath', xql: 'actor_process_image_path', udm: 'principal.process.file.full_path' },
        'CommandLine':          { splunk: 'CommandLine',  elastic: 'process.command_line', kql_sec: null,       kql_dev: 'InitiatingProcessCommandLine',    cb: 'cmdline',        vql: 'CommandLine',      s1: 'SrcProcCmdLine',   xql: 'actor_process_command_line', udm: 'principal.process.command_line' },
        'User':                 { splunk: 'User',         elastic: 'user.name',            kql_sec: null,       kql_dev: 'InitiatingProcessAccountName',    cb: 'username',       vql: 'User',             s1: 'SrcProcUser',      xql: 'actor_primary_username',    udm: 'principal.user.userid' },
        'DestinationIp':        { splunk: 'dest_ip',      elastic: 'destination.ip',       kql_sec: null,       kql_dev: 'RemoteIP',                        cb: 'netconn_ipv4',   vql: 'DestinationIp',    s1: 'DstIp',            xql: 'action_remote_ip',          udm: 'target.ip' },
        'DestinationPort':      { splunk: 'dest_port',    elastic: 'destination.port',     kql_sec: null,       kql_dev: 'RemotePort',                      cb: 'netconn_port',   vql: 'DestinationPort',  s1: 'DstPort',          xql: 'action_remote_port',        udm: 'target.port' },
        'DestinationHostname':  { splunk: 'dest',         elastic: 'destination.domain',   kql_sec: null,       kql_dev: 'RemoteUrl',                       cb: 'netconn_domain', vql: 'DestinationHostname', s1: 'DstDns',         xql: 'action_remote_hostname',    udm: 'target.hostname' },
        'SourceIp':             { splunk: 'src_ip',       elastic: 'source.ip',            kql_sec: null,       kql_dev: 'LocalIP',                         cb: null,             vql: 'SourceIp',         s1: 'SrcIp',            xql: 'action_local_ip',           udm: 'principal.ip' },
        'SourcePort':           { splunk: 'src_port',     elastic: 'source.port',          kql_sec: null,       kql_dev: 'LocalPort',                       cb: null,             vql: 'SourcePort',       s1: 'SrcPort',          xql: 'action_local_port',         udm: 'principal.port' },
        'Protocol':             { splunk: 'transport',    elastic: 'network.transport',    kql_sec: null,       kql_dev: 'Protocol',                        cb: 'netconn_protocol', vql: 'Protocol',       s1: 'NetConnProtocol',  xql: 'action_network_protocol',   udm: 'network.ip_protocol' },
        'ComputerName':         { splunk: 'ComputerName', elastic: 'host.name',            kql_sec: 'Computer', kql_dev: 'DeviceName',                      cb: 'hostname',       vql: 'Computer',         s1: 'EndpointName',     xql: 'agent_hostname',            udm: 'principal.hostname' },
        'Initiated':            { splunk: 'Initiated',    elastic: 'network.direction',    kql_sec: null,       kql_dev: null,                              cb: null,             vql: 'Initiated',        s1: null,               xql: null,                        udm: null },
    };

    // ── Windows: File Event / File Creation ──────────────────────────────
    // Sysmon Event IDs 11, 23, 26
    const FILE_EVENT = {
        'EventID':          { splunk: 'EventCode',       elastic: 'event.code',           kql_sec: 'EventID',  kql_dev: null,                               cb: null,           vql: 'EventID',       s1: 'EventId',        xql: null,                   udm: null },
        'TargetFilename':   { splunk: 'TargetFilename',  elastic: 'file.path',            kql_sec: null,       kql_dev: 'FolderPath',                       cb: null,           vql: 'TargetFilename', s1: 'TgtFilePath',    xql: 'action_file_path',     udm: 'target.file.full_path' },
        'Image':            { splunk: 'Image',           elastic: 'process.executable',   kql_sec: null,       kql_dev: 'InitiatingProcessFolderPath',      cb: 'process_name', vql: 'Image',         s1: 'SrcProcImagePath', xql: 'actor_process_image_path', udm: 'principal.process.file.full_path' },
        'CommandLine':      { splunk: 'CommandLine',     elastic: 'process.command_line', kql_sec: null,       kql_dev: 'InitiatingProcessCommandLine',     cb: 'cmdline',      vql: 'CommandLine',   s1: 'SrcProcCmdLine', xql: 'actor_process_command_line', udm: 'principal.process.command_line' },
        'User':             { splunk: 'User',            elastic: 'user.name',            kql_sec: null,       kql_dev: 'InitiatingProcessAccountName',     cb: 'username',     vql: 'User',          s1: 'SrcProcUser',    xql: 'actor_primary_username',   udm: 'principal.user.userid' },
        'CreationUtcTime':  { splunk: 'CreationUtcTime', elastic: 'file.created',         kql_sec: null,       kql_dev: 'Timestamp',                        cb: null,           vql: 'CreationUtcTime', s1: null,           xql: null,                   udm: null },
        'ComputerName':     { splunk: 'ComputerName',    elastic: 'host.name',            kql_sec: 'Computer', kql_dev: 'DeviceName',                       cb: 'hostname',     vql: 'Computer',      s1: 'EndpointName',   xql: 'agent_hostname',           udm: 'principal.hostname' },
    };

    // ── Windows: Registry Event ──────────────────────────────────────────
    // Sysmon Event IDs 12, 13, 14
    const REGISTRY_EVENT = {
        'EventID':        { splunk: 'EventCode',    elastic: 'event.code',             kql_sec: 'EventID',  kql_dev: null,                               cb: null,           vql: 'EventID',       s1: 'EventId',         xql: null,                      udm: null },
        'TargetObject':   { splunk: 'TargetObject', elastic: 'registry.path',          kql_sec: null,       kql_dev: 'RegistryKey',                      cb: null,           vql: 'TargetObject',  s1: 'RegistryKeyPath', xql: 'action_registry_key_name', udm: null },
        'Details':        { splunk: 'Details',      elastic: 'registry.data.strings',  kql_sec: null,       kql_dev: 'RegistryValueData',                cb: null,           vql: 'Details',       s1: 'RegistryValue',   xql: 'action_registry_value_data', udm: null },
        'Image':          { splunk: 'Image',        elastic: 'process.executable',     kql_sec: null,       kql_dev: 'InitiatingProcessFolderPath',      cb: 'process_name', vql: 'Image',         s1: 'SrcProcImagePath', xql: 'actor_process_image_path', udm: 'principal.process.file.full_path' },
        'User':           { splunk: 'User',         elastic: 'user.name',              kql_sec: null,       kql_dev: 'InitiatingProcessAccountName',     cb: 'username',     vql: 'User',          s1: 'SrcProcUser',     xql: 'actor_primary_username',  udm: 'principal.user.userid' },
        'ComputerName':   { splunk: 'ComputerName', elastic: 'host.name',              kql_sec: 'Computer', kql_dev: 'DeviceName',                       cb: 'hostname',     vql: 'Computer',      s1: 'EndpointName',    xql: 'agent_hostname',          udm: 'principal.hostname' },
    };

    // ── Windows: Security Event Log ──────────────────────────────────────
    const WINDOWS_SECURITY = {
        'EventID':           { splunk: 'EventCode',         elastic: 'event.code',                       kql_sec: 'EventID',          kql_dev: null,  cb: null,       vql: 'EventID',          s1: 'EventId',      xql: null,  udm: null },
        'SubjectUserName':   { splunk: 'SubjectUserName',   elastic: 'user.name',                        kql_sec: 'SubjectUserName',  kql_dev: null,  cb: 'username', vql: 'SubjectUserName',  s1: 'UserName',     xql: null,  udm: 'principal.user.userid' },
        'SubjectUserSid':    { splunk: 'SubjectUserSid',    elastic: 'user.id',                          kql_sec: 'SubjectUserSid',   kql_dev: null,  cb: null,       vql: 'SubjectUserSid',   s1: null,           xql: null,  udm: 'principal.user.windows_sid' },
        'SubjectDomainName': { splunk: 'SubjectDomainName', elastic: 'user.domain',                      kql_sec: 'SubjectDomainName', kql_dev: null, cb: null,       vql: 'SubjectDomainName', s1: null,           xql: null,  udm: null },
        'TargetUserName':    { splunk: 'TargetUserName',    elastic: 'user.target.name',                 kql_sec: 'TargetUserName',   kql_dev: null,  cb: null,       vql: 'TargetUserName',   s1: null,           xql: null,  udm: 'target.user.userid' },
        'TargetDomainName':  { splunk: 'TargetDomainName',  elastic: 'user.target.domain',               kql_sec: 'TargetDomainName', kql_dev: null,  cb: null,       vql: 'TargetDomainName', s1: null,           xql: null,  udm: null },
        'LogonType':         { splunk: 'LogonType',         elastic: 'winlog.event_data.LogonType',      kql_sec: 'LogonType',        kql_dev: null,  cb: null,       vql: 'LogonType',        s1: 'LogonType',    xql: null,  udm: 'extensions.auth.auth_details' },
        'WorkstationName':   { splunk: 'WorkstationName',   elastic: 'source.domain',                   kql_sec: 'WorkstationName',  kql_dev: null,  cb: 'hostname', vql: 'WorkstationName',  s1: 'EndpointName', xql: null,  udm: null },
        'IpAddress':         { splunk: 'IpAddress',         elastic: 'source.ip',                       kql_sec: 'IpAddress',        kql_dev: null,  cb: null,       vql: 'IpAddress',        s1: 'SrcIp',        xql: null,  udm: 'principal.ip' },
        'IpPort':            { splunk: 'IpPort',            elastic: 'source.port',                     kql_sec: 'IpPort',           kql_dev: null,  cb: null,       vql: 'IpPort',           s1: null,           xql: null,  udm: 'principal.port' },
        'ComputerName':      { splunk: 'ComputerName',      elastic: 'host.name',                       kql_sec: 'Computer',         kql_dev: 'DeviceName', cb: 'hostname', vql: 'ComputerName', s1: 'EndpointName', xql: 'agent_hostname', udm: 'principal.hostname' },
        'ServiceName':       { splunk: 'ServiceName',       elastic: 'service.name',                    kql_sec: 'ServiceName',      kql_dev: null,  cb: null,       vql: 'ServiceName',      s1: 'ServiceName',  xql: null,  udm: 'target.resource.name' },
        'ObjectName':        { splunk: 'ObjectName',        elastic: 'file.name',                       kql_sec: 'ObjectName',       kql_dev: null,  cb: null,       vql: 'ObjectName',       s1: null,           xql: null,  udm: 'target.file.full_path' },
        'PrivilegeList':     { splunk: 'PrivilegeList',     elastic: 'winlog.event_data.PrivilegeList',  kql_sec: 'PrivilegeList',    kql_dev: null,  cb: null,       vql: 'PrivilegeList',    s1: null,           xql: null,  udm: null },
    };

    // ── Windows: DNS Query ───────────────────────────────────────────────
    const DNS_QUERY = {
        'QueryName':    { splunk: 'QueryName',    elastic: 'dns.question.name', kql_sec: null, kql_dev: 'RemoteUrl',                            cb: 'netconn_domain', vql: 'QueryName',    s1: 'Dns.Request',  xql: 'action_dns_query_name',   udm: 'network.dns.questions.name' },
        'QueryType':    { splunk: 'QueryType',    elastic: 'dns.question.type', kql_sec: null, kql_dev: null,                                   cb: null,             vql: 'QueryType',    s1: null,           xql: null,                      udm: 'network.dns.questions.type' },
        'QueryResults': { splunk: 'QueryResults', elastic: 'dns.answers',       kql_sec: null, kql_dev: null,                                   cb: null,             vql: 'QueryResults', s1: 'Dns.Response', xql: null,                      udm: 'network.dns.answers.data' },
        'Image':        { splunk: 'Image',        elastic: 'process.executable', kql_sec: null, kql_dev: 'InitiatingProcessFolderPath',          cb: 'process_name',   vql: 'Image',        s1: 'SrcProcImagePath', xql: 'actor_process_image_path', udm: 'principal.process.file.full_path' },
        'User':         { splunk: 'User',         elastic: 'user.name',          kql_sec: null, kql_dev: 'InitiatingProcessAccountName',         cb: 'username',       vql: 'User',         s1: 'SrcProcUser',  xql: 'actor_primary_username',  udm: 'principal.user.userid' },
        'ComputerName': { splunk: 'ComputerName', elastic: 'host.name',          kql_sec: 'Computer', kql_dev: 'DeviceName',                    cb: 'hostname',       vql: 'Computer',     s1: 'EndpointName', xql: 'agent_hostname',          udm: 'principal.hostname' },
    };

    // ── Windows: Image Load ──────────────────────────────────────────────
    const IMAGE_LOAD = {
        'EventID':         { splunk: 'EventCode',      elastic: 'event.code',                kql_sec: 'EventID', kql_dev: null,                               cb: null,       vql: 'EventID',      s1: 'EventId',      xql: null,                   udm: null },
        'Image':           { splunk: 'Image',          elastic: 'process.executable',        kql_sec: null,      kql_dev: 'InitiatingProcessFolderPath',      cb: 'process_name', vql: 'Image',      s1: 'SrcProcImagePath', xql: 'actor_process_image_path', udm: 'principal.process.file.full_path' },
        'ImageLoaded':     { splunk: 'ImageLoaded',    elastic: 'dll.path',                  kql_sec: null,      kql_dev: 'FolderPath',                       cb: null,       vql: 'ImageLoaded',  s1: 'ModulePath',   xql: 'action_module_path',   udm: 'target.file.full_path' },
        'SignatureStatus': { splunk: 'SignatureStatus', elastic: 'dll.code_signature.status', kql_sec: null,      kql_dev: null,                               cb: null,       vql: 'SignatureStatus', s1: null,          xql: null,                   udm: null },
        'Signed':          { splunk: 'Signed',         elastic: 'dll.code_signature.signed', kql_sec: null,      kql_dev: null,                               cb: null,       vql: 'Signed',       s1: null,           xql: null,                   udm: null },
        'User':            { splunk: 'User',           elastic: 'user.name',                 kql_sec: null,      kql_dev: 'InitiatingProcessAccountName',     cb: 'username', vql: 'User',         s1: 'SrcProcUser',  xql: 'actor_primary_username', udm: 'principal.user.userid' },
        'ComputerName':    { splunk: 'ComputerName',   elastic: 'host.name',                 kql_sec: 'Computer', kql_dev: 'DeviceName',                      cb: 'hostname', vql: 'Computer',     s1: 'EndpointName', xql: 'agent_hostname',       udm: 'principal.hostname' },
    };

    // ── KQL table selection for each logsource ──────────────────────────
    // Returns { securityEvent, defenderTable } strings
    const KQL_TABLES = {
        'windows/process_creation': {
            sentinel: 'SecurityEvent\n| where EventID == 4688',
            defender: 'DeviceProcessEvents'
        },
        'windows/network_connection': {
            sentinel: 'DeviceNetworkEvents',
            defender: 'DeviceNetworkEvents'
        },
        'windows/file_event': {
            sentinel: 'DeviceFileEvents',
            defender: 'DeviceFileEvents'
        },
        'windows/file_creation': {
            sentinel: 'DeviceFileEvents',
            defender: 'DeviceFileEvents'
        },
        'windows/registry_event': {
            sentinel: 'DeviceRegistryEvents',
            defender: 'DeviceRegistryEvents'
        },
        'windows/registry_set': {
            sentinel: 'DeviceRegistryEvents',
            defender: 'DeviceRegistryEvents'
        },
        'windows/registry_add': {
            sentinel: 'DeviceRegistryEvents',
            defender: 'DeviceRegistryEvents'
        },
        'windows/image_load': {
            sentinel: 'DeviceImageLoadEvents',
            defender: 'DeviceImageLoadEvents'
        },
        'windows/dns_query': {
            sentinel: 'DeviceNetworkEvents\n| where ActionType == "DnsQueryResponse"',
            defender: 'DeviceNetworkEvents\n| where ActionType == "DnsQueryResponse"'
        },
        'windows/security': {
            sentinel: 'SecurityEvent',
            defender: null
        },
        'windows/system': {
            sentinel: 'Event\n| where Source == "System"',
            defender: null
        },
        'windows/application': {
            sentinel: 'Event\n| where Source == "Application"',
            defender: null
        },
        // Registry sub-categories (same tables as registry_event)
        'windows/registry_delete': {
            sentinel: 'DeviceRegistryEvents',
            defender: 'DeviceRegistryEvents'
        },
        'windows/registry_rename': {
            sentinel: 'DeviceRegistryEvents',
            defender: 'DeviceRegistryEvents'
        },
        // Sysmon-sourced variants
        'windows/sysmon/process_creation': {
            sentinel: 'SecurityEvent\n| where EventID == 1',
            defender: 'DeviceProcessEvents'
        },
        'windows/sysmon/network_connection': {
            sentinel: 'DeviceNetworkEvents',
            defender: 'DeviceNetworkEvents'
        },
        'windows/sysmon/file_event': {
            sentinel: 'DeviceFileEvents',
            defender: 'DeviceFileEvents'
        },
        'windows/sysmon/registry_event': {
            sentinel: 'DeviceRegistryEvents',
            defender: 'DeviceRegistryEvents'
        },
        'windows/sysmon/image_load': {
            sentinel: 'DeviceImageLoadEvents',
            defender: 'DeviceImageLoadEvents'
        },
        'windows/sysmon/dns_query': {
            sentinel: 'DeviceNetworkEvents\n| where ActionType == "DnsQueryResponse"',
            defender: 'DeviceNetworkEvents\n| where ActionType == "DnsQueryResponse"'
        },
        // PowerShell / WMI
        'windows/powershell': {
            sentinel: 'Event\n| where Source == "Microsoft-Windows-PowerShell"',
            defender: 'DeviceEvents\n| where ActionType startswith "PowerShell"'
        },
        'windows/powershell/operational': {
            sentinel: 'Event\n| where Source == "Microsoft-Windows-PowerShell"',
            defender: 'DeviceEvents\n| where ActionType startswith "PowerShell"'
        },
        'windows/wmi_event': {
            sentinel: 'DeviceEvents\n| where ActionType startswith "Wmi"',
            defender: 'DeviceEvents\n| where ActionType startswith "Wmi"'
        },
        // Process / driver events (generic)
        'windows/driver_load': {
            sentinel: 'DeviceImageLoadEvents\n| where InitiatingProcessFileName == "System"',
            defender: 'DeviceImageLoadEvents'
        },
        // Linux logsources
        'linux/process_creation': {
            sentinel: 'Syslog\n| where Facility == "user"',
            defender: null
        },
        'linux/network_connection': {
            sentinel: 'CommonSecurityLog\n| where DeviceVendor == "Linux"',
            defender: null
        },
        'linux/file_event': {
            sentinel: 'Syslog\n| where Facility == "kern"',
            defender: null
        },
        'linux/dns_query': {
            sentinel: 'CommonSecurityLog\n| where DeviceVendor == "Linux"',
            defender: null
        },
        // macOS logsources
        'macos/process_creation': {
            sentinel: 'Syslog\n| where Computer contains "mac"',
            defender: null
        },
        'macos/network_connection': {
            sentinel: 'Syslog\n| where Computer contains "mac"',
            defender: null
        },
        'macos/file_event': {
            sentinel: 'Syslog\n| where Computer contains "mac"',
            defender: null
        },
    };

    // ── Velociraptor artifact mapping ────────────────────────────────────
    const VQL_ARTIFACTS = {
        'windows/process_creation':    'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Security.evtx")',
        'windows/sysmon/process_creation': 'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/network_connection':  'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/sysmon/network_connection': 'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/file_event':          'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/file_creation':       'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/sysmon/file_event':   'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/registry_event':      'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/registry_add':        'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/registry_delete':     'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/registry_rename':     'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/sysmon/registry_event': 'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/sysmon/registry_add': 'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/sysmon/registry_delete': 'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/sysmon/registry_rename': 'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/image_load':          'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/sysmon/image_load':   'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/dns_query':           'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/sysmon/dns_query':    'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/driver_load':         'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx")',
        'windows/security':            'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Security.evtx")',
        'windows/system':              'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/System.evtx")',
        'windows/application':         'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Application.evtx")',
        'windows/powershell':          'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx")',
        'windows/powershell/operational': 'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx")',
        'windows/wmi_event':           'Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Microsoft-Windows-WMI-Activity%4Operational.evtx")',
        'linux/process_creation':      'Linux.Sys.Pslist',
        'linux/network_connection':    'Linux.Network.Netstat',
    };

    // ────────────────────────────────────────────────────────────────────
    // Public API
    // ────────────────────────────────────────────────────────────────────
    function getLogsourceKey(logsource) {
        const product  = (logsource.product  || '').toLowerCase();
        const category = (logsource.category || '').toLowerCase();
        const service  = (logsource.service  || '').toLowerCase();
        if (product && category) return `${product}/${category}`;
        if (product && service)  return `${product}/${service}`;
        if (product)             return product;
        return '';
    }

    function getFieldMap(logsource) {
        const key = getLogsourceKey(logsource);
        switch (key) {
            case 'windows/process_creation': return PROCESS_CREATION;
            case 'windows/network_connection': return NETWORK_CONNECTION;
            case 'windows/file_event':
            case 'windows/file_creation':    return FILE_EVENT;
            case 'windows/registry_event':
            case 'windows/registry_set':
            case 'windows/registry_add':
            case 'windows/registry_delete':
            case 'windows/registry_rename':  return REGISTRY_EVENT;
            case 'windows/security':         return WINDOWS_SECURITY;
            case 'windows/dns_query':        return DNS_QUERY;
            case 'windows/image_load':       return IMAGE_LOAD;
            default: return null;
        }
    }

    /**
     * Map a Sigma field name to the backend-specific field name.
     * @param {string}  fieldName  - Sigma field name
     * @param {object}  logsource  - Sigma logsource object
     * @param {string}  backend    - Backend key (splunk|elastic|kql_sec|kql_dev|cb|vql)
     * @param {boolean} strict     - When true, return null for any unmapped field instead
     *                               of falling back to the original field name (passthrough).
     *                               Use strict=true in real backends so cloud/unrecognised
     *                               fields are silently filtered rather than emitted verbatim.
     */
    function mapField(fieldName, logsource, backend, strict = false) {
        const map = getFieldMap(logsource);
        if (map && map[fieldName] && map[fieldName][backend] !== undefined) {
            return map[fieldName][backend]; // may be null if explicitly unsupported
        }
        // No explicit mapping found
        if (strict) return null; // caller wants strict: unknown → unsupported
        return fieldName;        // default: passthrough
    }

    function getKqlTable(logsource, useDefender = false) {
        const key = getLogsourceKey(logsource);
        const entry = KQL_TABLES[key];
        if (!entry) return null;
        return useDefender ? (entry.defender || entry.sentinel) : entry.sentinel;
    }

    function getVqlArtifact(logsource) {
        const product  = (logsource.product  || '').toLowerCase();
        const category = (logsource.category || '').toLowerCase();
        const service  = (logsource.service  || '').toLowerCase();

        if (product === 'windows' && service === 'sysmon' && category === 'process_creation') {
            return VQL_ARTIFACTS['windows/sysmon/process_creation'];
        }
        const key = getLogsourceKey(logsource);
        return VQL_ARTIFACTS[key] || null;
    }

    /**
     * Returns true when fieldName appears in ANY of the known Sigma field tables.
     * Used by generic backends to distinguish genuinely unmapped Sigma fields
     * (e.g. EventID, Image, CommandLine) from completely alien fields that should
     * be dropped (e.g. cloud-service fields like "actions" or "auditType.category").
     */
    function isKnownField(fieldName) {
        return [
            PROCESS_CREATION, NETWORK_CONNECTION, FILE_EVENT,
            REGISTRY_EVENT, WINDOWS_SECURITY, DNS_QUERY, IMAGE_LOAD,
        ].some(table => Object.prototype.hasOwnProperty.call(table, fieldName));
    }

    return {
        PROCESS_CREATION,
        NETWORK_CONNECTION,
        FILE_EVENT,
        REGISTRY_EVENT,
        WINDOWS_SECURITY,
        DNS_QUERY,
        IMAGE_LOAD,
        KQL_TABLES,
        VQL_ARTIFACTS,
        getLogsourceKey,
        getFieldMap,
        mapField,
        isKnownField,
        getKqlTable,
        getVqlArtifact,
    };

})();
