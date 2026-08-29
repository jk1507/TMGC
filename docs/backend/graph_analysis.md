# backend/graph_analysis.py - Graph-Based Domain Analysis

Maps relationships between domains to detect hidden malicious infrastructure.

## Features
- Domain clustering & grouping
- Shared infrastructure detection (IP, NS, SSL cert)
- Link traversal & redirect chain graphing
- WHOIS record relationship mapping
- GNN-ready feature extraction

## Data Classes

### `DomainNode`
Graph node representing a domain.
- IP addresses, nameservers, registrar
- SSL issuer, ASN, hosting provider
- Risk score and tags

### `GraphEdge`
Relationship edge between domains.
- Relationship type (shared_ip, shared_ns, shared_ssl, redirect, subdomain, whois_match)
- Weight and evidence

### `InfrastructureCluster`
Cluster of domains sharing infrastructure.
- Shared IPs, nameservers, SSL issuer
- Risk level and findings

### `GraphAnalysisResult`
Complete graph analysis result.

## Classes

### `DomainRelationshipGraph`
In-memory graph of domain relationships.

**Methods:**
- `add_node(domain, **kwargs)`: Add/update domain node
- `add_edge(source, target, relationship, weight, evidence)`: Add relationship
- `get_neighbors(domain)`: Get neighboring domains
- `find_paths(source, target, max_depth=5)`: BFS path finding
- `detect_clusters()`: Find connected components
- `to_networkx()`: Export to networkx for GNN analysis
- `compute_centrality()`: Degree centrality for each domain

## Functions

### `analyze_domain_graph(target_domain, dns_data, whois_data, ssl_data, related_domains, ct_subdomains)`
Perform graph-based domain relationship analysis.

**Returns dict with:**
- `graph_features`: ML-ready feature vector
- `clusters`: Infrastructure clusters
- `suspicious_paths`: Paths through relationship graph
- `domain_risks`: Per-domain risk scores
- `findings`: Analysis findings
- `score`: Overall graph risk score 0-100

### `build_domain_graph(target_domain, ...)`
Build domain relationship graph from intelligence data.

### `_extract_graph_features(graph)`
Extract graph-level features for ML classification.

### `_assess_cluster_risk(cluster)`
Assess risk level of infrastructure cluster.
