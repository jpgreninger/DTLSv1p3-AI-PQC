/*
 @licstart  The following is the entire license notice for the JavaScript code in this file.

 The MIT License (MIT)

 Copyright (C) 1997-2020 by Dimitri van Heesch

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 @licend  The above is the entire license notice for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "DTLS v1.3 Implementation", "index.html", [
    [ "DTLS v1.3 DoS Protection Implementation", "index.html", "index" ],
    [ "ACK Processing Integration with DTLS v1.3 Handshake State Machine", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html", [
      [ "Overview", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md84", null ],
      [ "Architecture", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md85", [
        [ "Components", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md86", null ],
        [ "Integration Points", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md87", null ]
      ] ],
      [ "State Machine Integration", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md88", [
        [ "ACK Processing States", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md89", null ],
        [ "Message Flow", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md90", null ]
      ] ],
      [ "Implementation Details", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md91", [
        [ "Connection Class Changes", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md92", [
          [ "New Methods", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md93", null ],
          [ "HandshakeManager Integration", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md94", null ]
        ] ],
        [ "ACK Message Handling", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md95", [
          [ "Automatic ACK Generation", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md96", null ],
          [ "ACK Processing Logic", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md97", null ]
        ] ],
        [ "Timeout Processing", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md98", [
          [ "Periodic Timeout Checks", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md99", null ],
          [ "Retransmission Strategy", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md100", null ]
        ] ]
      ] ],
      [ "Configuration Options", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md101", [
        [ "ConnectionConfig Integration", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md102", null ],
        [ "HandshakeManager Configuration", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md103", null ]
      ] ],
      [ "Error Handling", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md104", [
        [ "Timeout Scenarios", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md105", null ],
        [ "ACK Validation", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md106", null ],
        [ "Error Events", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md107", null ]
      ] ],
      [ "Statistics and Monitoring", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md108", [
        [ "Handshake Statistics", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md109", null ],
        [ "HandshakeManager Statistics", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md110", null ]
      ] ],
      [ "Usage Examples", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md111", [
        [ "Basic Integration", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md112", null ],
        [ "Event Handling", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md113", null ]
      ] ],
      [ "Performance Considerations", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md114", [
        [ "Optimization Features", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md115", null ],
        [ "Network Adaptivity", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md116", null ]
      ] ],
      [ "Testing", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md117", null ],
      [ "Future Enhancements", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md118", [
        [ "Potential Improvements", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md119", null ],
        [ "Integration Points", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md120", null ]
      ] ],
      [ "Conclusion", "md_docs_2ACK__STATE__MACHINE__INTEGRATION.html#autotoc_md121", null ]
    ] ],
    [ "DTLS v1.3 API Documentation", "md_docs_2API__DOCUMENTATION.html", [
      [ "Table of Contents", "md_docs_2API__DOCUMENTATION.html#autotoc_md123", null ],
      [ "Quick Start", "md_docs_2API__DOCUMENTATION.html#autotoc_md124", [
        [ "Basic Client Connection", "md_docs_2API__DOCUMENTATION.html#autotoc_md125", null ],
        [ "Basic Server Setup", "md_docs_2API__DOCUMENTATION.html#autotoc_md126", null ]
      ] ],
      [ "Core API", "md_docs_2API__DOCUMENTATION.html#autotoc_md127", [
        [ "Types and Constants", "md_docs_2API__DOCUMENTATION.html#autotoc_md128", null ],
        [ "Result Type System", "md_docs_2API__DOCUMENTATION.html#autotoc_md129", null ]
      ] ],
      [ "Connection Management", "md_docs_2API__DOCUMENTATION.html#autotoc_md130", [
        [ "Connection Class", "md_docs_2API__DOCUMENTATION.html#autotoc_md131", null ],
        [ "Connection Configuration", "md_docs_2API__DOCUMENTATION.html#autotoc_md132", null ],
        [ "Connection Events", "md_docs_2API__DOCUMENTATION.html#autotoc_md133", null ],
        [ "Connection Manager", "md_docs_2API__DOCUMENTATION.html#autotoc_md134", null ]
      ] ],
      [ "Cryptographic Interface", "md_docs_2API__DOCUMENTATION.html#autotoc_md135", [
        [ "Provider Factory", "md_docs_2API__DOCUMENTATION.html#autotoc_md136", null ],
        [ "Crypto Provider Interface", "md_docs_2API__DOCUMENTATION.html#autotoc_md137", null ],
        [ "Provider Manager", "md_docs_2API__DOCUMENTATION.html#autotoc_md138", null ]
      ] ],
      [ "Protocol Layer", "md_docs_2API__DOCUMENTATION.html#autotoc_md139", [
        [ "Record Layer Interface", "md_docs_2API__DOCUMENTATION.html#autotoc_md140", null ],
        [ "Handshake Manager", "md_docs_2API__DOCUMENTATION.html#autotoc_md141", null ]
      ] ],
      [ "Memory Management", "md_docs_2API__DOCUMENTATION.html#autotoc_md142", [
        [ "Buffer Management", "md_docs_2API__DOCUMENTATION.html#autotoc_md143", null ]
      ] ],
      [ "Error Handling", "md_docs_2API__DOCUMENTATION.html#autotoc_md144", [
        [ "Error Types and Codes", "md_docs_2API__DOCUMENTATION.html#autotoc_md145", null ],
        [ "Error Recovery", "md_docs_2API__DOCUMENTATION.html#autotoc_md146", null ]
      ] ],
      [ "Configuration", "md_docs_2API__DOCUMENTATION.html#autotoc_md147", [
        [ "System Configuration", "md_docs_2API__DOCUMENTATION.html#autotoc_md148", null ]
      ] ],
      [ "Performance Monitoring", "md_docs_2API__DOCUMENTATION.html#autotoc_md149", [
        [ "Metrics Collection", "md_docs_2API__DOCUMENTATION.html#autotoc_md150", null ]
      ] ],
      [ "Security Features", "md_docs_2API__DOCUMENTATION.html#autotoc_md151", [
        [ "DoS Protection", "md_docs_2API__DOCUMENTATION.html#autotoc_md152", null ]
      ] ],
      [ "Examples", "md_docs_2API__DOCUMENTATION.html#autotoc_md153", [
        [ "Complete Client Example", "md_docs_2API__DOCUMENTATION.html#autotoc_md154", null ],
        [ "Complete Server Example", "md_docs_2API__DOCUMENTATION.html#autotoc_md155", null ],
        [ "Early Data (0-RTT) Example", "md_docs_2API__DOCUMENTATION.html#autotoc_md156", null ]
      ] ],
      [ "License", "md_docs_2API__DOCUMENTATION.html#autotoc_md158", null ],
      [ "Support", "md_docs_2API__DOCUMENTATION.html#autotoc_md159", null ]
    ] ],
    [ "API Documentation Validation Report", "md_docs_2API__DOCUMENTATION__VALIDATION.html", [
      [ "Documentation Completeness Assessment", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md161", [
        [ "Core API Coverage", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md162", [
          [ "Main Components Documented", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md163", null ],
          [ "Type System Coverage", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md164", null ],
          [ "Advanced Features Coverage", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md165", null ]
        ] ],
        [ "SystemC API Coverage", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md166", null ],
        [ "Example Code Validation", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md167", null ],
        [ "Documentation Quality Metrics", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md168", null ],
        [ "Compliance Verification", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md169", [
          [ "RFC 9147 Compliance", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md170", null ],
          [ "C++20 Standards Compliance", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md171", null ],
          [ "SystemC TLM-2.0 Compliance", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md172", null ]
        ] ],
        [ "Documentation Structure Validation", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md173", [
          [ "Hierarchical Organization", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md174", null ],
          [ "Consistency", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md175", null ],
          [ "Accessibility", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md176", null ]
        ] ],
        [ "Integration Validation", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md177", [
          [ "Build System Integration", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md178", null ],
          [ "Development Workflow", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md179", null ]
        ] ],
        [ "Areas of Excellence", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md180", null ],
        [ "Validation Summary", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md181", null ],
        [ "Recommendations for Maintenance", "md_docs_2API__DOCUMENTATION__VALIDATION.html#autotoc_md182", null ]
      ] ]
    ] ],
    [ "DTLS v1.3 API Quick Reference", "md_docs_2API__QUICK__REFERENCE.html", [
      [ "Essential Headers", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md185", null ],
      [ "Quick Start Patterns", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md186", [
        [ "Client Connection", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md187", null ],
        [ "Server Setup", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md188", null ]
      ] ],
      [ "Core Types Reference", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md189", null ],
      [ "Enums Quick Reference", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md190", [
        [ "CipherSuite", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md191", null ],
        [ "ConnectionState", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md192", null ],
        [ "ConnectionEvent", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md193", null ]
      ] ],
      [ "Error Handling Patterns", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md194", [
        [ "Result Type Usage", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md195", null ],
        [ "Common Error Codes", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md196", null ]
      ] ],
      [ "Connection Management", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md197", [
        [ "Basic Operations", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md198", null ],
        [ "Event Handling", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md199", null ],
        [ "Configuration Options", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md200", null ]
      ] ],
      [ "Crypto Provider Management", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md201", [
        [ "Factory Usage", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md202", null ],
        [ "Provider Capabilities", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md203", null ]
      ] ],
      [ "Memory Management", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md204", [
        [ "Buffer Operations", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md205", null ],
        [ "Zero-Copy Operations", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md206", null ]
      ] ],
      [ "Advanced Features", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md207", [
        [ "Early Data (0-RTT)", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md208", null ],
        [ "Connection ID Migration", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md209", null ],
        [ "Key Updates", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md210", null ],
        [ "Session Management", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md211", null ]
      ] ],
      [ "Performance Monitoring", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md212", [
        [ "Connection Statistics", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md213", null ],
        [ "System Metrics", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md214", null ]
      ] ],
      [ "Security Features", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md215", [
        [ "DoS Protection", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md216", null ],
        [ "Certificate Validation", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md217", null ]
      ] ],
      [ "Common Patterns", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md218", [
        [ "Async Operations", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md219", null ],
        [ "Error Recovery", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md220", null ],
        [ "Multi-threaded Usage", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md221", null ]
      ] ],
      [ "Debugging and Logging", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md222", [
        [ "Debug Configuration", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md223", null ],
        [ "Performance Profiling", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md224", null ]
      ] ],
      [ "Build Integration", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md225", [
        [ "CMake Integration", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md226", null ],
        [ "Compiler Requirements", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md227", null ]
      ] ],
      [ "Common Error Solutions", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md228", null ],
      [ "Best Practices", "md_docs_2API__QUICK__REFERENCE.html#autotoc_md229", null ]
    ] ],
    [ "DTLS v1.3 Architecture Documentation", "md_docs_2ARCHITECTURE__DOCUMENTATION.html", [
      [ "Table of Contents", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md231", null ],
      [ "Overview", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md232", [
        [ "Key Architectural Goals", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md233", null ]
      ] ],
      [ "Architectural Principles", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md234", [
        [ "1. <strong>Separation of Concerns</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md235", null ],
        [ "2. <strong>Dependency Inversion</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md236", null ],
        [ "3. <strong>Interface Segregation</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md237", null ],
        [ "4. <strong>Open/Closed Principle</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md238", null ],
        [ "5. <strong>Single Responsibility</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md239", null ]
      ] ],
      [ "Core Design Patterns", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md240", [
        [ "1. <strong>Abstract Factory Pattern</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md241", null ],
        [ "2. <strong>Strategy Pattern</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md242", null ],
        [ "3. <strong>RAII (Resource Acquisition Is Initialization)</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md243", null ],
        [ "4. <strong>Observer Pattern</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md244", null ],
        [ "5. <strong>Command Pattern</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md245", null ],
        [ "6. <strong>Template Method Pattern</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md246", null ],
        [ "7. <strong>Adapter Pattern</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md247", null ]
      ] ],
      [ "System Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md248", [
        [ "High-Level Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md249", null ],
        [ "Component Interaction Flow", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md250", null ],
        [ "Data Flow Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md251", null ]
      ] ],
      [ "Component Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md252", [
        [ "1. <strong>Connection Management Layer</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md253", null ],
        [ "2. <strong>Protocol Layer</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md254", null ],
        [ "3. <strong>Cryptographic Layer</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md255", null ],
        [ "4. <strong>Security Layer</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md256", null ],
        [ "5. <strong>Memory Management Layer</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md257", null ],
        [ "6. <strong>Transport Layer</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md258", null ]
      ] ],
      [ "SystemC Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md259", [
        [ "TLM-2.0 Integration Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md260", null ],
        [ "Core Protocol Separation", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md261", null ],
        [ "TLM Extension Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md262", null ]
      ] ],
      [ "Design Decisions and Trade-offs", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md263", [
        [ "1. <strong>Result<T> vs Exceptions</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md264", null ],
        [ "2. <strong>Provider Pattern for Cryptography</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md265", null ],
        [ "3. <strong>Zero-Copy Buffer Management</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md266", null ],
        [ "4. <strong>Dual Implementation (C++ + SystemC)</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md267", null ],
        [ "5. <strong>Memory Pool Strategy</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md268", null ],
        [ "6. <strong>Thread Safety Strategy</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md269", null ],
        [ "7. <strong>Error Recovery Strategy</strong>", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md270", null ]
      ] ],
      [ "Performance Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md271", [
        [ "Memory Optimization Strategy", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md272", null ],
        [ "Performance Metrics", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md273", null ]
      ] ],
      [ "Security Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md274", [
        [ "Defense-in-Depth Strategy", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md275", null ],
        [ "Attack Mitigation Matrix", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md276", null ],
        [ "Security Event Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md277", null ]
      ] ],
      [ "Testing Architecture", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md278", [
        [ "Test Infrastructure Pyramid", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md279", null ],
        [ "Test Categories", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md280", null ],
        [ "Test Design Patterns", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md281", [
          [ "Mock Provider Pattern", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md282", null ],
          [ "Test Fixture Pattern", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md283", null ]
        ] ]
      ] ],
      [ "Conclusion", "md_docs_2ARCHITECTURE__DOCUMENTATION.html#autotoc_md284", null ]
    ] ],
    [ "DTLS v1.3 Design Decisions and Trade-offs", "md_docs_2DESIGN__DECISIONS.html", [
      [ "Table of Contents", "md_docs_2DESIGN__DECISIONS.html#autotoc_md286", null ],
      [ "Overview", "md_docs_2DESIGN__DECISIONS.html#autotoc_md287", [
        [ "Decision Making Criteria", "md_docs_2DESIGN__DECISIONS.html#autotoc_md288", null ]
      ] ],
      [ "Core Architecture Decisions", "md_docs_2DESIGN__DECISIONS.html#autotoc_md289", [
        [ "Decision 1: Layered Architecture with Abstract Interfaces", "md_docs_2DESIGN__DECISIONS.html#autotoc_md290", null ],
        [ "Decision 2: Dual Implementation Strategy (C++ + SystemC)", "md_docs_2DESIGN__DECISIONS.html#autotoc_md292", null ],
        [ "Decision 3: Component-Based Architecture", "md_docs_2DESIGN__DECISIONS.html#autotoc_md294", null ]
      ] ],
      [ "Error Handling Strategy", "md_docs_2DESIGN__DECISIONS.html#autotoc_md295", [
        [ "Decision 4: Result<T> Pattern Instead of Exceptions", "md_docs_2DESIGN__DECISIONS.html#autotoc_md296", null ],
        [ "Decision 5: Structured Error Hierarchy", "md_docs_2DESIGN__DECISIONS.html#autotoc_md298", null ]
      ] ],
      [ "Memory Management Decisions", "md_docs_2DESIGN__DECISIONS.html#autotoc_md299", [
        [ "Decision 6: Zero-Copy Buffer System with Reference Counting", "md_docs_2DESIGN__DECISIONS.html#autotoc_md300", null ],
        [ "Decision 7: Adaptive Memory Pool Strategy", "md_docs_2DESIGN__DECISIONS.html#autotoc_md302", null ]
      ] ],
      [ "Cryptographic Architecture", "md_docs_2DESIGN__DECISIONS.html#autotoc_md303", [
        [ "Decision 8: Provider Pattern for Cryptographic Operations", "md_docs_2DESIGN__DECISIONS.html#autotoc_md304", null ],
        [ "Decision 9: Constant-Time Operations for Security", "md_docs_2DESIGN__DECISIONS.html#autotoc_md306", null ]
      ] ],
      [ "Threading and Concurrency", "md_docs_2DESIGN__DECISIONS.html#autotoc_md307", [
        [ "Decision 10: Fine-Grained Locking with Lock-Free Operations", "md_docs_2DESIGN__DECISIONS.html#autotoc_md308", null ],
        [ "Decision 11: Thread-Safe Error Recovery", "md_docs_2DESIGN__DECISIONS.html#autotoc_md310", null ]
      ] ],
      [ "Performance Optimization", "md_docs_2DESIGN__DECISIONS.html#autotoc_md311", [
        [ "Decision 12: Hardware Acceleration Support", "md_docs_2DESIGN__DECISIONS.html#autotoc_md312", null ],
        [ "Decision 13: Zero-Copy Network Operations", "md_docs_2DESIGN__DECISIONS.html#autotoc_md314", null ]
      ] ],
      [ "Security Design", "md_docs_2DESIGN__DECISIONS.html#autotoc_md315", [
        [ "Decision 14: Defense-in-Depth Security Architecture", "md_docs_2DESIGN__DECISIONS.html#autotoc_md316", null ],
        [ "Decision 15: Comprehensive DoS Protection", "md_docs_2DESIGN__DECISIONS.html#autotoc_md318", null ]
      ] ],
      [ "SystemC Integration", "md_docs_2DESIGN__DECISIONS.html#autotoc_md319", [
        [ "Decision 16: Logic Duplication Elimination Pattern", "md_docs_2DESIGN__DECISIONS.html#autotoc_md320", null ],
        [ "Decision 17: TLM-2.0 Compliant Extensions", "md_docs_2DESIGN__DECISIONS.html#autotoc_md322", null ]
      ] ],
      [ "Testing Strategy", "md_docs_2DESIGN__DECISIONS.html#autotoc_md323", [
        [ "Decision 18: Multi-Layer Testing Architecture", "md_docs_2DESIGN__DECISIONS.html#autotoc_md324", null ],
        [ "Decision 19: Mock-Based Testing Strategy", "md_docs_2DESIGN__DECISIONS.html#autotoc_md326", null ]
      ] ],
      [ "Build System and Dependencies", "md_docs_2DESIGN__DECISIONS.html#autotoc_md327", [
        [ "Decision 20: Out-of-Source Build Requirement", "md_docs_2DESIGN__DECISIONS.html#autotoc_md328", null ],
        [ "Decision 21: Comprehensive Build Scripts", "md_docs_2DESIGN__DECISIONS.html#autotoc_md330", null ]
      ] ],
      [ "Conclusion", "md_docs_2DESIGN__DECISIONS.html#autotoc_md331", [
        [ "Key Success Metrics", "md_docs_2DESIGN__DECISIONS.html#autotoc_md332", null ],
        [ "Decision Impact Summary", "md_docs_2DESIGN__DECISIONS.html#autotoc_md333", null ]
      ] ]
    ] ],
    [ "DTLS v1.3 Early Data (0-RTT) Implementation", "md_docs_2EARLY__DATA__IMPLEMENTATION.html", [
      [ "Overview", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md335", null ],
      [ "Implementation Status", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md336", [
        [ "Completed Components", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md337", [
          [ "Week 1: Early Data Infrastructure ✅", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md338", null ],
          [ "Week 2: Early Data Integration ✅", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md339", null ]
        ] ]
      ] ],
      [ "Architecture", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md340", [
        [ "Core Components", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md341", [
          [ "1. Message Types (<tt>include/dtls/protocol/handshake.h</tt>)", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md342", null ],
          [ "2. Extension Support", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md343", null ],
          [ "3. Session Management (<tt>include/dtls/protocol/early_data.h</tt>)", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md344", null ],
          [ "4. Replay Protection", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md345", null ],
          [ "5. State Management", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md346", null ]
        ] ],
        [ "Connection API (<tt>include/dtls/connection.h</tt>)", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md347", [
          [ "Early Data Methods", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md348", null ],
          [ "Configuration", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md349", null ],
          [ "Events", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md350", null ]
        ] ]
      ] ],
      [ "Usage Examples", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md351", [
        [ "Basic Early Data Usage", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md352", null ],
        [ "Session Ticket Management", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md353", null ],
        [ "Server-Side Early Data Handling", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md354", null ]
      ] ],
      [ "Security Considerations", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md355", [
        [ "Replay Protection", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md356", null ],
        [ "Key Derivation", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md357", null ],
        [ "Limitations", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md358", null ]
      ] ],
      [ "Performance Impact", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md359", [
        [ "Benefits", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md360", null ],
        [ "Costs", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md361", null ]
      ] ],
      [ "File Structure", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md362", null ],
      [ "Testing", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md363", [
        [ "Example Application", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md364", null ],
        [ "Integration Points", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md365", null ]
      ] ],
      [ "Future Enhancements", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md366", [
        [ "Production Readiness", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md367", null ],
        [ "Advanced Features", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md368", null ]
      ] ],
      [ "Compliance", "md_docs_2EARLY__DATA__IMPLEMENTATION.html#autotoc_md369", null ]
    ] ],
    [ "DTLS v1.3 Error Handling System Documentation", "md_docs_2ERROR__HANDLING.html", [
      [ "Overview", "md_docs_2ERROR__HANDLING.html#autotoc_md371", null ],
      [ "Architecture", "md_docs_2ERROR__HANDLING.html#autotoc_md372", [
        [ "Core Components", "md_docs_2ERROR__HANDLING.html#autotoc_md373", null ],
        [ "Design Principles", "md_docs_2ERROR__HANDLING.html#autotoc_md374", null ]
      ] ],
      [ "RFC 9147 Compliance Features", "md_docs_2ERROR__HANDLING.html#autotoc_md375", [
        [ "Section 4.2.1: Invalid Record Handling", "md_docs_2ERROR__HANDLING.html#autotoc_md376", null ],
        [ "Transport-Specific Alert Policies", "md_docs_2ERROR__HANDLING.html#autotoc_md377", null ],
        [ "Fatal Alert Generation", "md_docs_2ERROR__HANDLING.html#autotoc_md378", null ],
        [ "Authentication Failure Tracking", "md_docs_2ERROR__HANDLING.html#autotoc_md379", null ]
      ] ],
      [ "API Reference", "md_docs_2ERROR__HANDLING.html#autotoc_md380", [
        [ "ErrorHandler", "md_docs_2ERROR__HANDLING.html#autotoc_md381", [
          [ "Core Configuration", "md_docs_2ERROR__HANDLING.html#autotoc_md382", null ],
          [ "Primary Methods", "md_docs_2ERROR__HANDLING.html#autotoc_md383", null ]
        ] ],
        [ "ErrorContext", "md_docs_2ERROR__HANDLING.html#autotoc_md384", [
          [ "Error Tracking", "md_docs_2ERROR__HANDLING.html#autotoc_md385", null ],
          [ "Pattern Analysis", "md_docs_2ERROR__HANDLING.html#autotoc_md386", null ]
        ] ],
        [ "AlertManager", "md_docs_2ERROR__HANDLING.html#autotoc_md387", [
          [ "Alert Generation", "md_docs_2ERROR__HANDLING.html#autotoc_md388", null ],
          [ "Alert Policy Configuration", "md_docs_2ERROR__HANDLING.html#autotoc_md389", null ]
        ] ],
        [ "ErrorReporter", "md_docs_2ERROR__HANDLING.html#autotoc_md390", [
          [ "Secure Reporting", "md_docs_2ERROR__HANDLING.html#autotoc_md391", null ],
          [ "Builder Pattern for Complex Reports", "md_docs_2ERROR__HANDLING.html#autotoc_md392", null ]
        ] ]
      ] ],
      [ "Usage Examples", "md_docs_2ERROR__HANDLING.html#autotoc_md393", [
        [ "Basic UDP Server Configuration", "md_docs_2ERROR__HANDLING.html#autotoc_md394", null ],
        [ "Processing Invalid Records", "md_docs_2ERROR__HANDLING.html#autotoc_md395", null ],
        [ "Security Incident Handling", "md_docs_2ERROR__HANDLING.html#autotoc_md396", null ],
        [ "Production Deployment", "md_docs_2ERROR__HANDLING.html#autotoc_md397", null ]
      ] ],
      [ "SystemC Integration", "md_docs_2ERROR__HANDLING.html#autotoc_md398", [
        [ "TLM Error Extension", "md_docs_2ERROR__HANDLING.html#autotoc_md399", null ],
        [ "Error Injection for Testing", "md_docs_2ERROR__HANDLING.html#autotoc_md400", null ]
      ] ],
      [ "Performance Characteristics", "md_docs_2ERROR__HANDLING.html#autotoc_md401", [
        [ "Memory Usage", "md_docs_2ERROR__HANDLING.html#autotoc_md402", null ],
        [ "Processing Overhead", "md_docs_2ERROR__HANDLING.html#autotoc_md403", null ],
        [ "Scalability", "md_docs_2ERROR__HANDLING.html#autotoc_md404", null ]
      ] ],
      [ "Security Considerations", "md_docs_2ERROR__HANDLING.html#autotoc_md405", [
        [ "Information Disclosure Prevention", "md_docs_2ERROR__HANDLING.html#autotoc_md406", null ],
        [ "DoS Protection", "md_docs_2ERROR__HANDLING.html#autotoc_md407", null ],
        [ "Audit and Compliance", "md_docs_2ERROR__HANDLING.html#autotoc_md408", null ]
      ] ],
      [ "Testing", "md_docs_2ERROR__HANDLING.html#autotoc_md409", [
        [ "Unit Tests", "md_docs_2ERROR__HANDLING.html#autotoc_md410", null ],
        [ "RFC 9147 Compliance Tests", "md_docs_2ERROR__HANDLING.html#autotoc_md411", null ],
        [ "Integration Testing", "md_docs_2ERROR__HANDLING.html#autotoc_md412", null ],
        [ "Performance Benchmarking", "md_docs_2ERROR__HANDLING.html#autotoc_md413", null ]
      ] ],
      [ "Migration Guide", "md_docs_2ERROR__HANDLING.html#autotoc_md414", [
        [ "From Basic Error Handling", "md_docs_2ERROR__HANDLING.html#autotoc_md415", null ],
        [ "From Custom Alert Generation", "md_docs_2ERROR__HANDLING.html#autotoc_md416", null ]
      ] ],
      [ "Troubleshooting", "md_docs_2ERROR__HANDLING.html#autotoc_md417", [
        [ "Common Issues", "md_docs_2ERROR__HANDLING.html#autotoc_md418", null ],
        [ "Debug Configuration", "md_docs_2ERROR__HANDLING.html#autotoc_md419", null ]
      ] ],
      [ "Future Enhancements", "md_docs_2ERROR__HANDLING.html#autotoc_md420", null ],
      [ "References", "md_docs_2ERROR__HANDLING.html#autotoc_md421", null ],
      [ "Support", "md_docs_2ERROR__HANDLING.html#autotoc_md422", null ]
    ] ],
    [ "DTLS v1.3 Hardware Acceleration Framework", "md_docs_2HARDWARE__ACCELERATION.html", [
      [ "Overview", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md424", null ],
      [ "Architecture", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md425", [
        [ "Core Components", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md426", null ]
      ] ],
      [ "Supported Hardware Features", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md427", [
        [ "x86_64 Architecture", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md428", null ],
        [ "ARM64 Architecture", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md429", null ],
        [ "Security Hardware", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md430", null ]
      ] ],
      [ "API Usage", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md431", [
        [ "Basic Hardware Acceleration", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md432", null ],
        [ "Zero-Copy Operations", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md433", null ],
        [ "Batch Processing", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md434", null ],
        [ "Record Layer Acceleration", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md435", null ]
      ] ],
      [ "Performance Characteristics", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md436", [
        [ "Measured Performance Improvements", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md437", null ],
        [ "Memory Efficiency", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md438", null ],
        [ "Scalability", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md439", null ]
      ] ],
      [ "Configuration Options", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md440", [
        [ "Compile-Time Configuration", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md441", null ],
        [ "Runtime Configuration", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md442", null ],
        [ "Environment Variables", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md443", null ]
      ] ],
      [ "Hardware Detection", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md444", [
        [ "Automatic Detection", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md445", null ],
        [ "Capability Testing", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md446", null ]
      ] ],
      [ "Best Practices", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md447", [
        [ "1. Use Optimal Configuration", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md448", null ],
        [ "2. Enable Batch Processing for High Throughput", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md449", null ],
        [ "3. Monitor Performance", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md450", null ],
        [ "4. Handle Fallbacks Gracefully", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md451", null ]
      ] ],
      [ "Troubleshooting", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md452", [
        [ "Common Issues", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md453", null ],
        [ "Debug Information", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md454", null ]
      ] ],
      [ "Integration with Existing Code", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md455", null ],
      [ "Compliance and Security", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md456", null ],
      [ "Future Enhancements", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md457", null ],
      [ "Contributing", "md_docs_2HARDWARE__ACCELERATION.html#autotoc_md458", null ]
    ] ],
    [ "DTLS v1.3 Performance Characteristics", "md_docs_2PERFORMANCE__CHARACTERISTICS.html", [
      [ "Table of Contents", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md460", null ],
      [ "Executive Summary", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md461", [
        [ "<strong>🏆 Key Performance Achievements</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md462", null ],
        [ "<strong>Performance Summary</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md463", null ]
      ] ],
      [ "Performance Requirements", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md464", [
        [ "<strong>Production Performance Requirements</strong> (RFC 9147 Compliance)", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md465", [
          [ "<strong>Primary Performance Targets</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md466", null ],
          [ "<strong>Quality of Service Requirements</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md467", null ]
        ] ]
      ] ],
      [ "Benchmark Results", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md468", [
        [ "<strong>Comprehensive Performance Validation Results</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md469", [
          [ "<strong>Protocol Performance Benchmarks</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md470", null ],
          [ "<strong>Cryptographic Performance Benchmarks</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md471", null ],
          [ "<strong>Memory Performance Benchmarks</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md472", null ],
          [ "<strong>Network Performance Benchmarks</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md473", null ]
        ] ]
      ] ],
      [ "Performance Architecture", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md474", [
        [ "<strong>High-Performance Design Patterns</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md475", [
          [ "<strong>Zero-Copy Buffer Management</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md476", null ],
          [ "<strong>Adaptive Memory Pool System</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md477", null ],
          [ "<strong>Hardware-Accelerated Cryptography</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md478", null ]
        ] ],
        [ "<strong>Performance-Critical Path Optimization</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md479", [
          [ "<strong>Fast Path Record Processing</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md480", null ],
          [ "<strong>Connection State Machine Optimization</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md481", null ]
        ] ]
      ] ],
      [ "Memory Performance", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md482", [
        [ "<strong>Memory Efficiency Architecture</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md483", [
          [ "<strong>Connection Memory Profile</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md484", null ],
          [ "<strong>Memory Scaling Characteristics</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md485", null ],
          [ "<strong>Garbage Collection Performance</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md486", null ]
        ] ]
      ] ],
      [ "Cryptographic Performance", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md487", [
        [ "<strong>Crypto Provider Performance Analysis</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md488", [
          [ "<strong>AEAD Operations (AES-128-GCM) - Production Validated</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md489", null ],
          [ "<strong>Key Derivation Performance (HKDF-Expand-Label)</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md490", null ],
          [ "<strong>Random Number Generation Performance</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md491", null ]
        ] ],
        [ "<strong>Crypto Performance Optimization</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md492", [
          [ "<strong>Operation Batching and Caching</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md493", null ]
        ] ]
      ] ],
      [ "Network Performance", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md494", [
        [ "<strong>Network Throughput Characteristics</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md495", [
          [ "<strong>UDP Efficiency Metrics</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md496", null ],
          [ "<strong>Latency Characteristics</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md497", null ]
        ] ],
        [ "<strong>Scalability Performance</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md498", [
          [ "<strong>Concurrent Connection Handling</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md499", null ],
          [ "<strong>Resource Management Under Load</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md500", null ]
        ] ]
      ] ],
      [ "SystemC Performance Modeling", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md501", [
        [ "<strong>Hardware/Software Co-Design Performance Analysis</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md502", [
          [ "<strong>SystemC TLM Performance Modeling</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md503", null ],
          [ "<strong>Performance Analysis Framework</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md504", null ]
        ] ],
        [ "<strong>Hardware Platform Performance Characteristics</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md505", [
          [ "<strong>Platform-Specific Performance Models</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md506", null ]
        ] ]
      ] ],
      [ "Performance Monitoring", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md507", [
        [ "<strong>Real-Time Performance Monitoring System</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md508", [
          [ "<strong>Performance Metrics Collection</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md509", null ],
          [ "<strong>Performance Alert System</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md510", null ]
        ] ],
        [ "<strong>Performance Regression Testing</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md511", [
          [ "<strong>Continuous Performance Validation</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md512", null ]
        ] ]
      ] ],
      [ "Optimization Guidelines", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md513", [
        [ "<strong>Performance Optimization Best Practices</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md514", [
          [ "<strong>Application-Level Optimization</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md515", null ],
          [ "<strong>System-Level Optimization</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md516", null ]
        ] ],
        [ "<strong>Performance Tuning Guidelines</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md517", [
          [ "<strong>Connection-Specific Tuning</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md518", null ]
        ] ]
      ] ],
      [ "Production Deployment", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md519", [
        [ "<strong>Production Performance Guidelines</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md520", [
          [ "<strong>Deployment Configuration</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md521", null ],
          [ "<strong>Production Monitoring and Alerting</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md522", null ]
        ] ],
        [ "<strong>Performance Validation Checklist</strong>", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md523", [
          [ "<strong>Pre-Production Validation</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md524", null ],
          [ "<strong>Post-Deployment Validation</strong> ✅", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md525", null ]
        ] ]
      ] ],
      [ "Conclusion", "md_docs_2PERFORMANCE__CHARACTERISTICS.html#autotoc_md527", null ]
    ] ],
    [ "DTLS v1.3 SystemC TLM Security Assessment Report", "md_docs_2SECURITY__ASSESSMENT__REPORT.html", [
      [ "Executive Summary", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md550", [
        [ "Risk Assessment Summary", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md551", null ]
      ] ],
      [ "Critical Vulnerabilities (CVE-Style Ratings)", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md553", [
        [ "🔴 <strong>VULN-001: Simulation-Only Cryptographic Operations</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md554", null ],
        [ "🔴 <strong>VULN-002: Missing Input Validation on TLM Transactions</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md555", null ],
        [ "🔴 <strong>VULN-003: Race Conditions in Security-Critical Statistics</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md556", null ]
      ] ],
      [ "High Severity Vulnerabilities", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md558", [
        [ "🟠 <strong>VULN-004: Anti-Replay Window Integer Overflow</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md559", null ],
        [ "🟠 <strong>VULN-005: Memory Management Issues in TLM Extensions</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md560", null ],
        [ "🟠 <strong>VULN-006: Fragment Calculation Integer Overflow</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md561", null ],
        [ "🟠 <strong>VULN-007: Resource Exhaustion via Fragment Flooding</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md562", null ]
      ] ],
      [ "Medium Severity Vulnerabilities", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md564", [
        [ "🟡 <strong>VULN-008: Information Disclosure in Debug Output</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md565", null ],
        [ "🟡 <strong>VULN-009: Weak Random Number Generation Timing</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md566", null ]
      ] ],
      [ "Low Severity Issues", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md568", [
        [ "🟢 <strong>VULN-010: Resource Leak in Failed Operations</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md569", null ]
      ] ],
      [ "Attack Surface Analysis", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md571", [
        [ "Primary Attack Vectors", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md572", null ],
        [ "Trust Boundaries", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md573", null ]
      ] ],
      [ "Remediation Roadmap", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md575", [
        [ "Phase 1: Critical Security Fixes (1-2 weeks)", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md576", [
          [ "🔴 <strong>Priority 1: Implement Real Cryptography</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md577", null ],
          [ "🔴 <strong>Priority 2: Input Validation Framework</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md578", null ],
          [ "🔴 <strong>Priority 3: Fix Race Conditions</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md579", null ]
        ] ],
        [ "Phase 2: High Priority Fixes (1 week)", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md580", [
          [ "🟠 <strong>Priority 4: Protocol Security Hardening</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md581", null ],
          [ "🟠 <strong>Priority 5: Memory Safety</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md582", null ],
          [ "🟠 <strong>Priority 6: DoS Protection</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md583", null ]
        ] ],
        [ "Phase 3: Medium Priority Improvements (3-5 days)", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md584", [
          [ "🟡 <strong>Priority 7: Information Security</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md585", null ],
          [ "🟡 <strong>Priority 8: Side-Channel Resistance</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md586", null ]
        ] ],
        [ "Phase 4: Validation and Testing (1 week)", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md587", [
          [ "🔵 <strong>Security Testing Implementation</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md588", null ],
          [ "🔵 <strong>Security Documentation</strong>", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md589", null ]
        ] ]
      ] ],
      [ "Security Testing Requirements", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md591", [
        [ "Mandatory Security Tests", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md592", null ],
        [ "Security Validation Pipeline", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md593", null ]
      ] ],
      [ "Compliance and Regulatory Considerations", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md595", [
        [ "Security Standards Compliance", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md596", null ],
        [ "Regulatory Impact Assessment", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md597", null ]
      ] ],
      [ "Conclusion and Recommendations", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md599", [
        [ "Executive Summary", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md600", null ],
        [ "Risk Assessment", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md601", null ],
        [ "Business Impact", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md602", null ],
        [ "Technical Recommendations", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md603", null ],
        [ "Final Verdict", "md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md604", null ]
      ] ]
    ] ],
    [ "DTLS v1.3 Security Documentation", "md_docs_2SECURITY__DOCUMENTATION.html", [
      [ "Table of Contents", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md608", null ],
      [ "Overview", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md609", [
        [ "Security Philosophy", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md610", null ]
      ] ],
      [ "Security Assumptions", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md611", [
        [ "1. <strong>Cryptographic Assumptions</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md612", [
          [ "<strong>Strong Cryptographic Primitives</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md613", null ],
          [ "<strong>Secure Random Number Generation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md614", null ],
          [ "<strong>Key Derivation Security</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md615", null ]
        ] ],
        [ "2. <strong>Network Environment Assumptions</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md616", [
          [ "<strong>Untrusted Network</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md617", null ],
          [ "<strong>UDP Transport Properties</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md618", null ],
          [ "<strong>Denial-of-Service Environment</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md619", null ]
        ] ],
        [ "3. <strong>Implementation Environment Assumptions</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md620", [
          [ "<strong>Memory Safety</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md621", null ],
          [ "<strong>Timing Attack Resistance</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md622", null ],
          [ "<strong>Side-Channel Resistance</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md623", null ]
        ] ],
        [ "4. <strong>Operational Assumptions</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md624", [
          [ "<strong>Certificate Infrastructure</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md625", null ],
          [ "<strong>Key Management</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md626", null ],
          [ "<strong>Configuration Security</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md627", null ]
        ] ]
      ] ],
      [ "Threat Model", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md628", [
        [ "1. <strong>Network-Level Threats</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md629", [
          [ "<strong>Volumetric DoS Attacks</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md630", null ],
          [ "<strong>Protocol-Level DoS Attacks</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md631", null ],
          [ "<strong>Man-in-the-Middle Attacks</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md632", null ]
        ] ],
        [ "2. <strong>Cryptographic Threats</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md633", [
          [ "<strong>Cipher Suite Downgrade Attacks</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md634", null ],
          [ "<strong>Key Compromise and Recovery</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md635", null ],
          [ "<strong>Timing and Side-Channel Attacks</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md636", null ]
        ] ],
        [ "3. <strong>Implementation Threats</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md637", [
          [ "<strong>Memory Corruption Vulnerabilities</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md638", null ],
          [ "<strong>Integer Overflow and Underflow</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md639", null ],
          [ "<strong>Race Conditions and Concurrency Issues</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md640", null ]
        ] ],
        [ "4. <strong>Protocol-Specific Threats</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md641", [
          [ "<strong>Replay Attacks</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md642", null ],
          [ "<strong>Fragmentation Attacks</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md643", null ],
          [ "<strong>Connection ID Attacks</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md644", null ]
        ] ]
      ] ],
      [ "Security Guarantees", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md645", [
        [ "1. <strong>Confidentiality Guarantees</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md646", [
          [ "<strong>Data Confidentiality</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md647", null ],
          [ "<strong>Forward Secrecy</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md648", null ],
          [ "<strong>Key Isolation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md649", null ]
        ] ],
        [ "2. <strong>Integrity Guarantees</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md650", [
          [ "<strong>Message Authentication</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md651", null ],
          [ "<strong>Handshake Integrity</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md652", null ],
          [ "<strong>Sequence Number Protection</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md653", null ]
        ] ],
        [ "3. <strong>Authenticity Guarantees</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md654", [
          [ "<strong>Peer Authentication</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md655", null ],
          [ "<strong>Message Origin Authentication</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md656", null ],
          [ "<strong>Non-Repudiation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md657", null ]
        ] ],
        [ "4. <strong>Availability Guarantees</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md658", [
          [ "<strong>DoS Protection</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md659", null ],
          [ "<strong>Resource Protection</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md660", null ],
          [ "**Graceful Degradation**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md661", null ]
        ] ]
      ] ],
      [ "Cryptographic Security Properties", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md662", [
        [ "1. **Cipher Suite Security**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md663", [
          [ "**AEAD Cipher Security**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md664", null ],
          [ "**Key Exchange Security**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md665", null ],
          [ "**Digital Signature Security**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md666", null ]
        ] ],
        [ "2. **Key Derivation Security**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md667", [
          [ "**HKDF-Expand-Label**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md668", null ],
          [ "**Key Schedule Security**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md669", null ]
        ] ],
        [ "3. **Random Number Generation**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md670", [
          [ "**Entropy Sources**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md671", null ],
          [ "**CSPRNG Properties**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md672", null ]
        ] ]
      ] ],
      [ "Attack Mitigation Strategies", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md673", [
        [ "1. **Network Attack Mitigation**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md674", [
          [ "**Volumetric DoS Mitigation**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md675", null ],
          [ "**Protocol DoS Mitigation**", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md676", null ],
          [ "<strong>Man-in-the-Middle Attack Mitigation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md677", null ]
        ] ],
        [ "2. <strong>Cryptographic Attack Mitigation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md678", [
          [ "<strong>Timing Attack Mitigation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md679", null ],
          [ "<strong>Side-Channel Attack Mitigation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md680", null ],
          [ "<strong>Key Recovery Attack Mitigation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md681", null ]
        ] ],
        [ "3. <strong>Implementation Attack Mitigation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md682", [
          [ "<strong>Memory Corruption Mitigation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md683", null ],
          [ "<strong>Integer Overflow Mitigation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md684", null ],
          [ "<strong>Concurrency Attack Mitigation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md685", null ]
        ] ]
      ] ],
      [ "Security Architecture", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md686", [
        [ "1. <strong>Layered Security Model</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md687", [
          [ "<strong>Security Layer Stack</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md688", null ]
        ] ],
        [ "2. <strong>Security Component Architecture</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md689", [
          [ "<strong>DoS Protection System</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md690", null ],
          [ "<strong>Cryptographic Security Manager</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md691", null ],
          [ "<strong>Security Event System</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md692", null ]
        ] ],
        [ "3. <strong>Attack Surface Analysis</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md693", [
          [ "<strong>Network Attack Surface</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md694", null ],
          [ "<strong>Cryptographic Attack Surface</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md695", null ],
          [ "<strong>Memory Management Attack Surface</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md696", null ]
        ] ]
      ] ],
      [ "Compliance and Standards", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md697", [
        [ "1. <strong>RFC Compliance</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md698", [
          [ "<strong>RFC 9147 DTLS v1.3 Compliance</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md699", null ],
          [ "<strong>Related RFC Compliance</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md700", null ]
        ] ],
        [ "2. <strong>Security Standards Compliance</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md701", [
          [ "<strong>FIPS 140-2 Compliance</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md702", null ],
          [ "<strong>Common Criteria Compliance</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md703", null ],
          [ "<strong>Industry Standards</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md704", null ]
        ] ],
        [ "3. <strong>Regulatory Compliance</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md705", [
          [ "<strong>Data Protection Regulations</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md706", null ],
          [ "<strong>Export Control Compliance</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md707", null ]
        ] ]
      ] ],
      [ "Security Configuration Guide", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md708", [
        [ "1. <strong>Production Deployment Security</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md709", [
          [ "<strong>Minimum Security Configuration</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md710", null ],
          [ "<strong>Cryptographic Configuration</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md711", null ],
          [ "<strong>Certificate Configuration</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md712", null ]
        ] ],
        [ "2. <strong>Security Hardening Checklist</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md713", [
          [ "<strong>Deployment Security Checklist</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md714", null ],
          [ "<strong>Operational Security Checklist</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md715", null ]
        ] ],
        [ "3. <strong>Configuration Validation</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md716", [
          [ "<strong>Security Configuration Testing</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md717", null ]
        ] ]
      ] ],
      [ "Security Monitoring and Incident Response", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md718", [
        [ "1. <strong>Security Event Monitoring</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md719", [
          [ "<strong>Real-Time Security Monitoring</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md720", null ],
          [ "<strong>Attack Pattern Detection</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md721", null ]
        ] ],
        [ "2. <strong>Automated Incident Response</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md722", [
          [ "<strong>Incident Response Framework</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md723", null ],
          [ "<strong>Emergency Response Procedures</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md724", null ]
        ] ],
        [ "3. <strong>Security Audit and Forensics</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md725", [
          [ "<strong>Security Audit Framework</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md726", null ]
        ] ]
      ] ],
      [ "Security Testing and Validation", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md727", [
        [ "1. <strong>Security Test Framework</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md728", [
          [ "<strong>Comprehensive Security Testing</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md729", null ]
        ] ],
        [ "2. <strong>Penetration Testing</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md730", [
          [ "<strong>Automated Penetration Testing</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md731", null ]
        ] ],
        [ "3. <strong>Security Validation Results</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md732", [
          [ "<strong>Current Security Validation Status</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md733", null ]
        ] ]
      ] ],
      [ "Conclusion", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md734", [
        [ "<strong>Security Achievements</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md735", null ],
        [ "<strong>Security Guarantees</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md736", null ],
        [ "<strong>Compliance and Standards</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md737", null ],
        [ "<strong>Production Readiness</strong>", "md_docs_2SECURITY__DOCUMENTATION.html#autotoc_md738", null ]
      ] ]
    ] ],
    [ "Security Documentation Validation Report", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html", [
      [ "Documentation Completeness Assessment", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md740", [
        [ "Security Documentation Coverage", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md741", null ]
      ] ],
      [ "Major Security Documentation Sections", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md742", null ],
      [ "Detailed Coverage Analysis", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md743", [
        [ "1. Security Assumptions ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md744", [
          [ "Cryptographic Assumptions", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md745", null ],
          [ "Network Environment Assumptions", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md746", null ],
          [ "Implementation Environment Assumptions", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md747", null ]
        ] ],
        [ "2. Threat Model ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md748", [
          [ "Network-Level Threats", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md749", null ],
          [ "Cryptographic Threats", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md750", null ],
          [ "Implementation Threats", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md751", null ],
          [ "Protocol-Specific Threats", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md752", null ]
        ] ],
        [ "3. Security Guarantees ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md753", [
          [ "Confidentiality Guarantees", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md754", null ],
          [ "Integrity Guarantees", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md755", null ],
          [ "Authenticity Guarantees", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md756", null ],
          [ "Availability Guarantees", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md757", null ]
        ] ],
        [ "4. Cryptographic Security Properties ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md758", [
          [ "Cipher Suite Security", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md759", null ],
          [ "Key Derivation Security", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md760", null ]
        ] ],
        [ "5. Attack Mitigation Strategies ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md761", [
          [ "Network Attack Mitigation", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md762", null ],
          [ "Cryptographic Attack Mitigation", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md763", null ],
          [ "Implementation Attack Mitigation", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md764", null ]
        ] ],
        [ "6. Security Architecture ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md765", [
          [ "Layered Security Model", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md766", null ],
          [ "Security Component Architecture", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md767", null ],
          [ "Attack Surface Analysis", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md768", null ]
        ] ],
        [ "7. Compliance and Standards ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md769", [
          [ "RFC Compliance", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md770", null ],
          [ "Security Standards Compliance", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md771", null ],
          [ "Regulatory Compliance", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md772", null ]
        ] ],
        [ "8. Security Configuration Guide ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md773", [
          [ "Production Deployment Security", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md774", null ],
          [ "Security Hardening Checklist", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md775", null ]
        ] ],
        [ "9. Security Monitoring and Incident Response ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md776", [
          [ "Security Event Monitoring", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md777", null ],
          [ "Automated Incident Response", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md778", null ],
          [ "Security Audit and Forensics", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md779", null ]
        ] ],
        [ "10. Security Testing and Validation ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md780", [
          [ "Security Test Framework", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md781", null ],
          [ "Penetration Testing", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md782", null ],
          [ "Security Validation Results", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md783", null ]
        ] ]
      ] ],
      [ "Security Documentation Quality Metrics", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md784", null ],
      [ "Security Standards Compliance Validation", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md785", [
        [ "RFC 9147 Security Requirements ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md786", null ],
        [ "Industry Security Standards ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md787", null ],
        [ "Enterprise Security Requirements ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md788", null ]
      ] ],
      [ "Documentation Structure Validation", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md789", [
        [ "Hierarchical Organization ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md790", null ],
        [ "Consistency and Quality ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md791", null ],
        [ "Accessibility and Usability ✅ COMPLETE", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md792", null ]
      ] ],
      [ "Integration with Existing Documentation", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md793", [
        [ "Architecture Documentation Integration ✅ VERIFIED", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md794", null ],
        [ "API Documentation Integration ✅ VERIFIED", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md795", null ],
        [ "Development Documentation Integration ✅ VERIFIED", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md796", null ]
      ] ],
      [ "Areas of Excellence", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md797", null ],
      [ "Validation Summary", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md798", [
        [ "Recommendations for Maintenance", "md_docs_2SECURITY__DOCUMENTATION__VALIDATION.html#autotoc_md799", null ]
      ] ]
    ] ],
    [ "DTLS v1.3 Security Validation Suite", "md_docs_2SECURITY__VALIDATION__SUITE.html", [
      [ "Overview", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md802", null ],
      [ "Implementation Status", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md803", [
        [ "✅ <strong>Completed Components</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md804", [
          [ "<strong>1. Comprehensive Security Test Framework</strong> (<tt>tests/security/security_validation_suite.h/.cpp</tt>)", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md805", null ],
          [ "<strong>2. Attack Simulation Scenarios</strong> (Implemented in <tt>comprehensive_security_tests.cpp</tt>)", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md806", null ],
          [ "<strong>3. Advanced Fuzzing and Protocol Validation</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md807", null ],
          [ "<strong>4. Timing Attack Resistance Testing</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md808", null ],
          [ "<strong>5. Side-Channel Resistance Validation</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md809", null ],
          [ "<strong>6. Memory Safety Validation</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md810", null ],
          [ "<strong>7. Cryptographic Compliance Testing</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md811", null ],
          [ "<strong>8. Security Requirements Compliance</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md812", null ],
          [ "<strong>9. Comprehensive Threat Model Validation</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md813", null ],
          [ "<strong>10. Security Assessment Report Generation</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md814", null ]
        ] ]
      ] ],
      [ "Architecture", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md816", [
        [ "Core Classes and Components", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md817", [
          [ "<strong>SecurityValidationSuite</strong> (Base Test Class)", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md818", null ],
          [ "<strong>SecurityMetrics</strong> (Comprehensive Metrics Tracking)", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md819", null ],
          [ "<strong>SecurityEvent</strong> (Event Classification System)", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md820", null ]
        ] ]
      ] ],
      [ "Usage Examples", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md822", [
        [ "<strong>Basic Security Validation</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md823", null ],
        [ "<strong>Specific Security Test Categories</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md824", null ],
        [ "<strong>Programmatic Usage</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md825", null ]
      ] ],
      [ "Test Coverage", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md827", [
        [ "<strong>Attack Simulation Coverage</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md828", null ],
        [ "<strong>Fuzzing Test Coverage</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md829", null ],
        [ "<strong>Cryptographic Compliance Coverage</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md830", null ],
        [ "<strong>Performance and Timing Coverage</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md831", null ]
      ] ],
      [ "Security Requirements Validation", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md833", [
        [ "<strong>Mandatory Requirements</strong> (Must Pass for Production)", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md834", null ],
        [ "<strong>Quality Gates</strong> (Must Meet Thresholds)", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md835", null ]
      ] ],
      [ "Report Generation", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md837", [
        [ "<strong>JSON Report</strong> (Machine-Readable)", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md838", null ],
        [ "<strong>HTML Report</strong> (Visual Dashboard)", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md839", null ],
        [ "<strong>Text Report</strong> (Human-Readable Summary)", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md840", null ]
      ] ],
      [ "Integration Points", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md842", [
        [ "<strong>Existing Codebase Integration</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md843", null ],
        [ "<strong>Build System Integration</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md844", null ]
      ] ],
      [ "Production Deployment", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md846", [
        [ "<strong>Security Validation Checklist</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md847", null ],
        [ "<strong>Continuous Security Monitoring</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md848", null ]
      ] ],
      [ "File Structure", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md850", null ],
      [ "Next Steps for Production", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md852", [
        [ "<strong>Immediate Actions</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md853", null ],
        [ "<strong>Future Enhancements</strong>", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md854", null ]
      ] ],
      [ "Compliance Summary", "md_docs_2SECURITY__VALIDATION__SUITE.html#autotoc_md856", null ]
    ] ],
    [ "DTLS v1.3 SystemC TLM API Documentation", "md_docs_2SYSTEMC__API__DOCUMENTATION.html", [
      [ "Table of Contents", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md858", null ],
      [ "Overview", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md859", [
        [ "Key Features", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md860", null ]
      ] ],
      [ "SystemC Components", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md861", [
        [ "Base Includes", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md862", null ],
        [ "Core Component Hierarchy", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md863", null ]
      ] ],
      [ "TLM Interfaces", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md864", [
        [ "DTLS TLM Extensions", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md865", null ],
        [ "TLM Sockets and Interfaces", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md866", null ]
      ] ],
      [ "Protocol Stack Model", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md867", [
        [ "Main Protocol Stack Component", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md868", null ],
        [ "Subcomponent Models", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md869", [
          [ "Record Layer Model", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md870", null ],
          [ "Crypto Engine Model", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md871", null ]
        ] ]
      ] ],
      [ "Timing Models", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md872", [
        [ "Configurable Timing Framework", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md873", null ]
      ] ],
      [ "Communication Channels", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md874", [
        [ "DTLS-Specific Channels", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md875", null ]
      ] ],
      [ "Testbenches", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md876", [
        [ "Protocol Verification Testbench", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md877", null ]
      ] ],
      [ "Performance Analysis", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md878", [
        [ "Performance Monitoring and Analysis", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md879", null ]
      ] ],
      [ "Examples", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md880", [
        [ "Basic SystemC DTLS Client-Server", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md881", null ],
        [ "Performance Benchmarking Example", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md882", null ]
      ] ],
      [ "Building and Running SystemC Models", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md884", [
        [ "CMake Integration", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md885", null ],
        [ "Compilation and Execution", "md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md886", null ]
      ] ]
    ] ],
    [ "SystemC Architecture Documentation", "md_docs_2SYSTEMC__ARCHITECTURE.html", [
      [ "Table of Contents", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md888", null ],
      [ "Overview", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md889", [
        [ "Key SystemC Architecture Goals", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md890", null ]
      ] ],
      [ "SystemC TLM Architecture", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md891", [
        [ "High-Level SystemC Architecture", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md892", null ],
        [ "SystemC Module Hierarchy", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md893", null ]
      ] ],
      [ "Core Protocol Separation Pattern", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md894", [
        [ "The Logic Duplication Elimination Architecture", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md895", null ],
        [ "Benefits of Core Protocol Separation", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md896", null ],
        [ "Core Protocol Components", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md897", null ]
      ] ],
      [ "TLM Extensions Design", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md898", [
        [ "DTLS-Specific TLM Extensions", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md899", null ],
        [ "TLM Socket Design", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md900", null ]
      ] ],
      [ "Timing Models Architecture", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md901", [
        [ "Configurable Timing Framework", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md902", null ],
        [ "Timing Model Implementations", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md903", [
          [ "1. Approximate Timing Model (Fast Simulation)", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md904", null ],
          [ "2. Cycle-Accurate Timing Model (Detailed Simulation)", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md905", null ]
        ] ],
        [ "Power Modeling Extension", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md906", null ]
      ] ],
      [ "Communication Channels", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md907", [
        [ "DTLS Message Channels", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md908", null ],
        [ "Network Simulation Channel", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md909", null ]
      ] ],
      [ "Testbench Architecture", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md910", [
        [ "Protocol Verification Testbench", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md911", null ]
      ] ],
      [ "Performance Analysis Framework", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md912", [
        [ "Performance Monitoring Architecture", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md913", null ]
      ] ],
      [ "Hardware/Software Co-design", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md914", [
        [ "Hardware Acceleration Modeling", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md915", null ],
        [ "Software Stack Integration", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md916", null ]
      ] ],
      [ "Conclusion", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md917", [
        [ "Key SystemC Architecture Benefits", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md918", null ],
        [ "Architecture Success Metrics", "md_docs_2SYSTEMC__ARCHITECTURE.html#autotoc_md919", null ]
      ] ]
    ] ],
    [ "Topics", "topics.html", "topics" ],
    [ "Namespaces", "namespaces.html", [
      [ "Namespace List", "namespaces.html", "namespaces_dup" ],
      [ "Namespace Members", "namespacemembers.html", [
        [ "All", "namespacemembers.html", "namespacemembers_dup" ],
        [ "Functions", "namespacemembers_func.html", "namespacemembers_func" ],
        [ "Variables", "namespacemembers_vars.html", null ],
        [ "Typedefs", "namespacemembers_type.html", null ],
        [ "Enumerations", "namespacemembers_enum.html", null ]
      ] ]
    ] ],
    [ "Classes", "annotated.html", [
      [ "Class List", "annotated.html", "annotated_dup" ],
      [ "Class Index", "classes.html", null ],
      [ "Class Hierarchy", "hierarchy.html", "hierarchy" ],
      [ "Class Members", "functions.html", [
        [ "All", "functions.html", "functions_dup" ],
        [ "Functions", "functions_func.html", "functions_func" ],
        [ "Variables", "functions_vars.html", "functions_vars" ],
        [ "Typedefs", "functions_type.html", null ],
        [ "Enumerations", "functions_enum.html", null ]
      ] ]
    ] ],
    [ "Files", "files.html", [
      [ "File List", "files.html", "files_dup" ],
      [ "File Members", "globals.html", [
        [ "All", "globals.html", null ],
        [ "Variables", "globals_vars.html", null ],
        [ "Typedefs", "globals_type.html", null ],
        [ "Macros", "globals_defs.html", null ]
      ] ]
    ] ],
    [ "Examples", "examples.html", "examples" ]
  ] ]
];

var NAVTREEINDEX =
[
"_2home_2jgreninger_2Work_2DTLSv1p3_2include_2dtls_2protocol_2version_manager_8h-example.html",
"classdtls_1_1v13_1_1connection_1_1advanced_1_1ManagedConnectionImpl.html#af89793500795eec8bf549d0eeec9653d",
"classdtls_1_1v13_1_1protocol_1_1ACK.html",
"classdtls_1_1v13_1_1protocol_1_1EndOfEarlyData.html#add2a3965ef24200c2ecb39c95acb1c5e",
"classdtls_1_1v13_1_1protocol_1_1ServerHello.html#af75f52ff3404dcbb10967d261d04cabb",
"crypto__utils_8cpp.html#a4d52c67845030652c76fc447112f6504",
"error_8h.html#aeaab1a668f345648ec3f402f6d41a243a8c1afb60bfa5a75fc40e9d6570fe906b",
"handshake_8h.html#a80472f8d158b569535b63d22d59e4ccd",
"leak__detection_8cpp.html#abf80225ced3091a3a1018e1e64e4427e",
"md_docs_2DESIGN__DECISIONS.html#autotoc_md316",
"md_docs_2SECURITY__ASSESSMENT__REPORT.html#autotoc_md601",
"md_docs_2SYSTEMC__API__DOCUMENTATION.html#autotoc_md864",
"namespacedtls_1_1v13.html#a454f2e2956822357a074530f22006b51",
"namespacedtls_1_1v13.html#aeaab1a668f345648ec3f402f6d41a243a8ae62732267a6e3c4444fb078bc7aadb",
"namespacedtls_1_1v13_1_1crypto_1_1advanced.html#a7889da9d63d1adde9dc95ab26f79a1beabe0f06b885034bb30ebb9fd868bba087",
"namespacedtls_1_1v13_1_1memory.html#a86a8918949d4247d0473a0bcb72e3654",
"namespacedtls_1_1v13_1_1protocol.html#aa52d8ccfbe0360143d96c083f5b5f85c",
"namespacemembers_o.html",
"result_8h_source.html",
"structdtls_1_1v13_1_1compatibility_1_1DTLS12CompatibilityContext.html#a4d28a679b413f2cc4f8770152dd2051c",
"structdtls_1_1v13_1_1crypto_1_1ConfigValidationIssue.html#ae9b33deb0be3f36c0d1f1e1c38fb248fa059e9861e0400dfbe05c98a841f3f96b",
"structdtls_1_1v13_1_1crypto_1_1MACValidationParams_1_1DTLSContext.html#a31b8140c4803c085cb4ae0fa1690566e",
"structdtls_1_1v13_1_1crypto_1_1advanced_1_1ExtendedAEADParams.html#ab1b32c09c22f7f7c5293505e6f77d514",
"structdtls_1_1v13_1_1memory_1_1ConnectionCharacteristics.html#a7cc6b9548c4afe7d2c5a39cc46de41b8",
"structdtls_1_1v13_1_1memory_1_1MemoryTestResult.html#ae359f7ab12b1d5320c7c2e0c37add851",
"structdtls_1_1v13_1_1monitoring_1_1PerformanceMetrics.html#a1d9c3b7dacf8815649c43ded712570c2",
"structdtls_1_1v13_1_1protocol_1_1DTLSCiphertext.html#a8bf8992f952d8df562408cefbb862d96",
"structdtls_1_1v13_1_1protocol_1_1HandshakeHeader.html#ae8778603bcd4847dddddaa92003970d8",
"structdtls_1_1v13_1_1security_1_1DoSProtectionStats.html#a3d61ea9408789db856d9f729ab4fc766",
"structdtls_1_1v13_1_1transport_1_1TransportConfig.html#a32f053b962b8e9fd07d0637a70fb46ac",
"types_8h.html#aeab29ce11310dc76ad87e254511f69d6a63cd4892307fe3cb50a670304109155d"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';