# `q_link` — Investigator & Auditor User Guide
## Automated Forensic Relationship & Intelligence Engine

---

### 1. Overview & Core Philosophy
Traditional forensic software forces investigators to execute manual, siloed searches across individual tools. **Q-Link** flips this paradigm:
Whenever any connected forensic tool (`Q-Bank`, `Q-Trail`, `Q-Mail`, `Q-Ledger`, `Q-Verify`, `Q-Scan`, `Q-Voice`) identifies an artifact, transaction, or finding, it automatically emits the event to Q-Link. Q-Link standardizes the entities, correlates direct and indirect relationships across the entire corporate repository, maintains a live relationship graph, and proactively alerts investigators to high-risk syndicates.

---

### 2. Key Capabilities & Investigative Workflows

#### 1. Interactive Relationship Canvas (Vis.js)
* **Visual Graph Exploration**: Color-coded node topology:
  * **Cyan**: Target Employees / Custodians
  * **Amber**: Vendors / Suppliers
  * **Emerald**: Bank Accounts
  * **Purple**: Purchase Orders & Invoices
  * **Rose**: Questioned Documents & PDF Hex Tampering
* **Physics & Layout Controls**: Use **Freeze** to stabilize complex networks, **Fit Canvas** to re-center, or the search input to zoom instantly to any entity.
* **Quick Filters**: Filter by entity classification (`All`, `Employees`, `Vendors`, `Documents`) to isolate specific layers.

#### 2. Forensic Copilot AI (Autonomous Tool-Calling Agent)
The built-in Copilot Agent is not a simple chatbot—it is an **agentic investigator with tool calling capabilities**:
* **Tools Executed**:
  * `get_entity_network(entity_name, max_hops)`: Explores multi-hop connections.
  * `find_paths_between(source, target)`: Maps hidden conduits and intermediary shells.
  * `get_entity_timeline(entity_name)`: Reconstructs chronological interactions.
  * `get_evidence_details(entity_name)`: Retrieves exact citations and deep URLs.
* **Suggested Queries**: Click quick prompts (e.g., *"Investigate Arun Kumar"*, *"Detect employee-vendor nexus"*, *"Trace tampered PDF documents"*) to initiate autonomous multi-tool reasoning.

#### 3. Entity Inspector & 100% Traceability
* Click any node in the graph to open the Inspector drawer:
  * **Canonical Identifier & Risk Score**: Normalizes legal entity variations (`ABC Enterprises Pvt Ltd` ↔ `A.B.C. Enterprises`).
  * **Direct Relationships List**: Lists outgoing and incoming ties with monetary volume and interaction counts.
  * **Granular Evidence Citations**: Provides 1-click drill-down links directly to the source record in Q-Bank, Q-Mail, Q-Verify, Q-Ledger, or Q-Trail.

#### 4. Reconstructed Chronological Sequence
* Displays the consolidated cross-tool timeline for the active entity (e.g. Email communication ➔ PO issued ➔ Bank transfer ➔ PDF alteration).

#### 5. Proactive Continuous Monitoring Alerts
* Automatically alerts investigators when:
  * An entity converges across $\ge 3$ distinct forensic tools.
  * A direct employee-to-vendor financial or private email connection is identified.
  * A historical entity from past inquiries resurfaces in a new audit.
* Click **Acknowledge** once reviewed.

---

### 3. Synchronizing Data
Click the **Sync All Tools** button in the top action bar to re-index all historical data across existing modules on demand.
