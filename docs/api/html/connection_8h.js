var connection_8h =
[
    [ "dtls::v13::ErrorRecoveryConfig", "structdtls_1_1v13_1_1ErrorRecoveryConfig.html", "structdtls_1_1v13_1_1ErrorRecoveryConfig" ],
    [ "dtls::v13::ErrorRecoveryState", "structdtls_1_1v13_1_1ErrorRecoveryState.html", "structdtls_1_1v13_1_1ErrorRecoveryState" ],
    [ "dtls::v13::ConnectionConfig", "structdtls_1_1v13_1_1ConnectionConfig.html", "structdtls_1_1v13_1_1ConnectionConfig" ],
    [ "dtls::v13::ConnectionStats", "structdtls_1_1v13_1_1ConnectionStats.html", "structdtls_1_1v13_1_1ConnectionStats" ],
    [ "dtls::v13::Connection", "classdtls_1_1v13_1_1Connection.html", "classdtls_1_1v13_1_1Connection" ],
    [ "dtls::v13::Connection::EarlyDataStats", "structdtls_1_1v13_1_1Connection_1_1EarlyDataStats.html", "structdtls_1_1v13_1_1Connection_1_1EarlyDataStats" ],
    [ "dtls::v13::Context", "classdtls_1_1v13_1_1Context.html", "classdtls_1_1v13_1_1Context" ],
    [ "dtls::v13::ConnectionManager", "classdtls_1_1v13_1_1ConnectionManager.html", "classdtls_1_1v13_1_1ConnectionManager" ],
    [ "ConnectionEventCallback", "connection_8h.html#a0822f6ecebdf163c5b140d5e15f949c9", null ],
    [ "ConnectionEvent", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1ea", [
      [ "HANDSHAKE_STARTED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa6bf13a53d9c94226f8951dfb66d4d15a", null ],
      [ "HANDSHAKE_COMPLETED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa6ecf9d772a6f2794fd5892f3e5ae42c5", null ],
      [ "HANDSHAKE_FAILED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa031450236028a5f782ed0cb7745935b3", null ],
      [ "DATA_RECEIVED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa1644a05bebcc7abb4e6aa13abc8a75e4", null ],
      [ "CONNECTION_CLOSED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa7009c19a45f0ebd4b14300665df173c5", null ],
      [ "ERROR_OCCURRED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa4533e10caf8298123e3c419b950158d0", null ],
      [ "ALERT_RECEIVED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaacf4b60b1f98dfc9848927a813e710a88", null ],
      [ "KEY_UPDATE_COMPLETED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa0c98443701a4058bec9dd0a07faba490", null ],
      [ "EARLY_DATA_ACCEPTED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaadaeebdf6ae5cfba70ebec4c8eaa5e8d5", null ],
      [ "EARLY_DATA_REJECTED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa0b11f9649b7300d89d9497c0ba2175b8", null ],
      [ "EARLY_DATA_RECEIVED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa8afd1d4aed541a8883eda178160095e4", null ],
      [ "NEW_SESSION_TICKET_RECEIVED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaaa22587386dffdd9f3b3bac7b9486eaaa", null ],
      [ "RECOVERY_STARTED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa4b610a4613fcf11d25506c94d47f6d9b", null ],
      [ "RECOVERY_SUCCEEDED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaaadd17119c64acb860f6b847f75082aae", null ],
      [ "RECOVERY_FAILED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaaa5ae556eafda7b1b2942433cd519c000", null ],
      [ "CONNECTION_DEGRADED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa1ee3b21d1c9a210b25bf308db5a9b487", null ],
      [ "CONNECTION_RESTORED", "connection_8h.html#ae6e8032c12417cb62fd44f38dfe5a1eaa64eeb264989a2976d7daf19a96c67092", null ]
    ] ],
    [ "ConnectionHealth", "connection_8h.html#a7546637dd240d5746d9f4b5ff3f14fd1", [
      [ "HEALTHY", "connection_8h.html#a7546637dd240d5746d9f4b5ff3f14fd1af068ebe4133e3e6563080836268ea979", null ],
      [ "DEGRADED", "connection_8h.html#a7546637dd240d5746d9f4b5ff3f14fd1a0021017005f0e5134b204c2e69d3d4ed", null ],
      [ "UNSTABLE", "connection_8h.html#a7546637dd240d5746d9f4b5ff3f14fd1ad3582680e9ce6bdf2e9791926bd99d5f", null ],
      [ "FAILING", "connection_8h.html#a7546637dd240d5746d9f4b5ff3f14fd1a04a6fafe393ceb9f5b6ce96aae00c8cb", null ],
      [ "FAILED", "connection_8h.html#a7546637dd240d5746d9f4b5ff3f14fd1ab9e14d9b2886bcff408b85aefa780419", null ]
    ] ],
    [ "RecoveryStrategy", "connection_8h.html#a3148a802c5357f5e43dcf3ba7a4a97b7", [
      [ "NONE", "connection_8h.html#a3148a802c5357f5e43dcf3ba7a4a97b7ab50339a10e1de285ac99d4c3990b8693", null ],
      [ "RETRY_IMMEDIATE", "connection_8h.html#a3148a802c5357f5e43dcf3ba7a4a97b7a31995be349b2c6ff457b653ced20296d", null ],
      [ "RETRY_WITH_BACKOFF", "connection_8h.html#a3148a802c5357f5e43dcf3ba7a4a97b7afdd0168686ad6e589e86cbb61a224079", null ],
      [ "GRACEFUL_DEGRADATION", "connection_8h.html#a3148a802c5357f5e43dcf3ba7a4a97b7aedb213ca9b6476838f1ed7f03f926d22", null ],
      [ "RESET_CONNECTION", "connection_8h.html#a3148a802c5357f5e43dcf3ba7a4a97b7a1af38ab8c9d27db122d0e538c9bc2305", null ],
      [ "FAILOVER", "connection_8h.html#a3148a802c5357f5e43dcf3ba7a4a97b7a36d31c88e39d3eb841007cbe5c9272dd", null ],
      [ "ABORT_CONNECTION", "connection_8h.html#a3148a802c5357f5e43dcf3ba7a4a97b7a78d9166d151784a4673ec9b57e275c1c", null ]
    ] ]
];