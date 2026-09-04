"""
Graph-Based Domain & Network Analysis Engine
=============================================
Maps relationships between domains, subdomains, WHOIS records,
SSL fingerprints, and DNS history to detect hidden malicious infrastructure.

Uses graph analytics (networkx-ready) for:
  - Domain clustering & grouping
  - Shared infrastructure detection (IP, NS, SSL cert)
  - Link traversal & redirect chain graphing
  - WHOIS record relationship mapping
  - GNN-ready feature extraction

Part of RETRO_INTEL / TMGC v4.0
"""

from __future__ import annotations

import re
import json
import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------
_NETWORKX_AVAILABLE = False
try:
    import networkx as nx
    _NETWORKX_AVAILABLE = True
except ImportError:
    nx = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class DomainNode:
    """Graph node representing a domain."""
    domain: str
    ip_addresses: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    registrar: str = ""
    creation_date: str = ""
    ssl_issuer: str = ""
    ssl_fingerprint: str = ""
    asn: str = ""
    hosting_provider: str = ""
    country: str = ""
    risk_score: int = 0
    tags: list[str] = field(default_factory=list)


@dataclass
class GraphEdge:
    """Graph edge representing a relationship between domains."""
    source: str
    target: str
    relationship: str  # shared_ip, shared_ns, shared_ssl, redirect, subdomain, whois_match
    weight: float = 1.0
    evidence: str = ""


@dataclass
class InfrastructureCluster:
    """A cluster of domains sharing infrastructure."""
    cluster_id: int
    domains: list[str] = field(default_factory=list)
    shared_ips: list[str] = field(default_factory=list)
    shared_nameservers: list[str] = field(default_factory=list)
    shared_ssl_issuer: str = ""
    risk_level: str = "unknown"
    risk_score: int = 0
    findings: list[str] = field(default_factory=list)
    cluster_type: str = "unknown"  # phishing_infrastructure, hosting_cluster, cdn_cluster


@dataclass
class GraphAnalysisResult:
    """Complete graph analysis result."""
    available: bool = True
    graph_built: bool = False
    node_count: int = 0
    edge_count: int = 0
    clusters: list[InfrastructureCluster] = field(default_factory=list)
    suspicious_paths: list[list[str]] = field(default_factory=list)
    domain_risks: dict[str, int] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    graph_features: dict[str, Any] = field(default_factory=dict)
    score: int = 0


# ---------------------------------------------------------------------------
# Graph Builder
# ---------------------------------------------------------------------------
class DomainRelationshipGraph:
    """
    In-memory graph of domain relationships.
    Uses adjacency list internally; can export to networkx for GNN analysis.
    """

    def __init__(self):
        self.nodes: dict[str, DomainNode] = {}
        self.edges: list[GraphEdge] = []
        self.adjacency: dict[str, list[tuple[str, GraphEdge]]] = defaultdict(list)

    def add_node(self, domain: str, **kwargs) -> DomainNode:
        """Add or update a domain node."""
        if domain not in self.nodes:
            self.nodes[domain] = DomainNode(domain=domain)
        node = self.nodes[domain]
        for key, value in kwargs.items():
            if hasattr(node, key) and value:
                setattr(node, key, value)
        return node

    def add_edge(self, source: str, target: str, relationship: str, weight: float = 1.0, evidence: str = "") -> None:
        """Add a relationship edge between two domains."""
        edge = GraphEdge(source=source, target=target, relationship=relationship, weight=weight, evidence=evidence)
        self.edges.append(edge)
        self.adjacency[source].append((target, edge))
        self.adjacency[target].append((source, edge))

    def get_neighbors(self, domain: str) -> list[tuple[str, GraphEdge]]:
        """Get all neighboring domains."""
        return self.adjacency.get(domain, [])

    def find_paths(self, source: str, target: str, max_depth: int = 5) -> list[list[str]]:
        """BFS to find all paths between two domains up to max_depth."""
        if source not in self.nodes or target not in self.nodes:
            return []

        paths = []
        queue = [(source, [source])]
        visited = set()

        while queue:
            current, path = queue.pop(0)
            if current == target:
                paths.append(path)
                continue
            if len(path) > max_depth:
                continue
            if current in visited:
                continue
            visited.add(current)

            for neighbor, edge in self.get_neighbors(current):
                if neighbor not in path:
                    queue.append((neighbor, path + [neighbor]))

        return paths

    def detect_clusters(self) -> list[InfrastructureCluster]:
        """Find connected components (clusters) using BFS."""
        visited = set()
        clusters = []
        cluster_id = 0

        for domain in self.nodes:
            if domain in visited:
                continue

            # BFS from this domain
            cluster_domains = []
            cluster_ips = set()
            cluster_ns = set()
            queue = [domain]
            cluster_visited = set()

            while queue:
                current = queue.pop(0)
                if current in cluster_visited:
                    continue
                cluster_visited.add(current)
                visited.add(current)
                cluster_domains.append(current)

                node = self.nodes.get(current)
                if node:
                    cluster_ips.update(node.ip_addresses)
                    cluster_ns.update(node.nameservers)

                for neighbor, edge in self.get_neighbors(current):
                    if neighbor not in cluster_visited:
                        queue.append(neighbor)

            if len(cluster_domains) > 1:
                cluster = InfrastructureCluster(
                    cluster_id=cluster_id,
                    domains=cluster_domains,
                    shared_ips=list(cluster_ips),
                    shared_nameservers=list(cluster_ns),
                )
                clusters.append(cluster)
                cluster_id += 1

        return clusters

    def to_networkx(self) -> Any:
        """Export to networkx graph for advanced GNN analysis."""
        if not _NETWORKX_AVAILABLE:
            return None
        G = nx.Graph()
        for domain, node in self.nodes.items():
            G.add_node(domain, **asdict(node))
        for edge in self.edges:
            G.add_edge(edge.source, edge.target, relationship=edge.relationship, weight=edge.weight)
        return G

    def compute_centrality(self) -> dict[str, float]:
        """Compute degree centrality for each domain."""
        centrality = {}
        total_nodes = len(self.nodes)
        if total_nodes <= 1:
            return {d: 0.0 for d in self.nodes}
        for domain in self.nodes:
            degree = len(self.adjacency.get(domain, []))
            centrality[domain] = degree / (total_nodes - 1)
        return centrality


# ---------------------------------------------------------------------------
# Graph Feature Extraction
# ---------------------------------------------------------------------------
def _extract_graph_features(graph: DomainRelationshipGraph) -> dict[str, Any]:
    """Extract graph-level features for ML classification."""
    features = {
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "density": 0.0,
        "avg_degree": 0.0,
        "max_degree": 0,
        "cluster_count": 0,
        "largest_cluster_size": 0,
        "unique_ips": 0,
        "unique_ns": 0,
        "shared_infrastructure_count": 0,
        "centrality_max": 0.0,
        "centrality_avg": 0.0,
    }

    n = len(graph.nodes)
    if n <= 1:
        return features

    # Density
    max_edges = n * (n - 1) / 2
    features["density"] = len(graph.edges) / max_edges if max_edges > 0 else 0

    # Degree stats
    degrees = [len(graph.adjacency.get(d, [])) for d in graph.nodes]
    features["avg_degree"] = sum(degrees) / len(degrees) if degrees else 0
    features["max_degree"] = max(degrees) if degrees else 0

    # Clusters
    clusters = graph.detect_clusters()
    features["cluster_count"] = len(clusters)
    if clusters:
        features["largest_cluster_size"] = max(len(c.domains) for c in clusters)

    # Infrastructure
    all_ips = set()
    all_ns = set()
    for node in graph.nodes.values():
        all_ips.update(node.ip_addresses)
        all_ns.update(node.nameservers)
    features["unique_ips"] = len(all_ips)
    features["unique_ns"] = len(all_ns)

    # Shared infrastructure edges
    shared_edges = [e for e in graph.edges if e.relationship in ("shared_ip", "shared_ns", "shared_ssl")]
    features["shared_infrastructure_count"] = len(shared_edges)

    # Centrality
    centrality = graph.compute_centrality()
    if centrality:
        features["centrality_max"] = max(centrality.values())
        features["centrality_avg"] = sum(centrality.values()) / len(centrality)

    return features


# ---------------------------------------------------------------------------
# Cluster Risk Assessment
# ---------------------------------------------------------------------------
def _assess_cluster_risk(cluster: InfrastructureCluster) -> InfrastructureCluster:
    """Assess the risk level of a infrastructure cluster."""
    findings = []
    risk = 0

    # Many domains sharing IPs = suspicious
    if len(cluster.domains) > 10:
        findings.append(f"Large cluster: {len(cluster.domains)} domains share infrastructure")
        risk += 20

    # Many domains sharing nameservers
    if len(cluster.shared_nameservers) > 0 and len(cluster.domains) > 5:
        ns = cluster.shared_nameservers[0] if cluster.shared_nameservers else "unknown"
        findings.append(f"Nameserver clustering: {len(cluster.domains)} domains share NS '{ns}'")
        risk += 15

    # Shared IP with many domains
    if len(cluster.shared_ips) > 0 and len(cluster.domains) > 3:
        findings.append(f"IP sharing: {len(cluster.domains)} domains resolve to {len(cluster.shared_ips)} IP(s)")
        risk += 10

    # Check for known malicious hosting patterns
    malicious_ns_patterns = ["ns1.", "ns2."]
    for ns in cluster.shared_nameservers:
        for pattern in malicious_ns_patterns:
            if ns.startswith(pattern) and ns.count('.') == 1:
                findings.append(f"Generic nameserver detected: {ns}")
                risk += 15

    cluster.findings = findings
    cluster.risk_score = min(risk, 100)

    if risk >= 60:
        cluster.risk_level = "critical"
    elif risk >= 40:
        cluster.risk_level = "high"
    elif risk >= 20:
        cluster.risk_level = "medium"
    else:
        cluster.risk_level = "low"

    return cluster


# ---------------------------------------------------------------------------
# Graph Construction from Domain Data
# ---------------------------------------------------------------------------
def build_domain_graph(
    target_domain: str,
    dns_data: dict[str, Any] = None,
    whois_data: dict[str, Any] = None,
    ssl_data: dict[str, Any] = None,
    related_domains: list[dict[str, Any]] = None,
    ct_subdomains: list[str] = None,
) -> DomainRelationshipGraph:
    """
    Build a domain relationship graph from available intelligence data.
    
    Args:
        target_domain: The domain being analyzed
        dns_data: DNS records (A, MX, NS)
        whois_data: WHOIS information
        ssl_data: SSL certificate details
        related_domains: List of related domain dicts (from CT logs, etc.)
        ct_subdomains: Subdomains from Certificate Transparency
    """
    graph = DomainRelationshipGraph()
    dns_data = dns_data or {}
    whois_data = whois_data or {}
    ssl_data = ssl_data or {}
    related_domains = related_domains or []
    ct_subdomains = ct_subdomains or []

    # Add target domain node
    target_ips = dns_data.get("a_records", [])
    if isinstance(target_ips, str):
        target_ips = [ip.strip() for ip in target_ips.split('\n') if ip.strip()]
    target_ns = dns_data.get("nameservers", [])

    graph.add_node(
        target_domain,
        ip_addresses=target_ips,
        nameservers=target_ns,
        registrar=whois_data.get("registrar", ""),
        creation_date=whois_data.get("creation_date", ""),
        ssl_issuer=ssl_data.get("issuer", ""),
        asn=whois_data.get("asn", ""),
    )

    # Add subdomains from CT logs
    for subdomain in ct_subdomains[:50]:
        clean_sub = subdomain.strip().lower()
        if clean_sub and clean_sub != target_domain:
            graph.add_node(clean_sub)
            graph.add_edge(
                target_domain, clean_sub,
                relationship="subdomain",
                weight=0.8,
                evidence=f"CT log subdomain: {clean_sub}"
            )

    # Add related domains and detect shared infrastructure
    for related in related_domains:
        r_domain = related.get("domain", "").strip().lower()
        if not r_domain or r_domain == target_domain:
            continue

        r_ips = related.get("ip_addresses", [])
        r_ns = related.get("nameservers", [])
        r_ssl = related.get("ssl_issuer", "")

        graph.add_node(
            r_domain,
            ip_addresses=r_ips,
            nameservers=r_ns if isinstance(r_ns, list) else [r_ns] if r_ns else [],
            ssl_issuer=r_ssl,
        )

        # Check shared IP
        shared_ips = set(target_ips) & set(r_ips)
        if shared_ips:
            graph.add_edge(
                target_domain, r_domain,
                relationship="shared_ip",
                weight=0.9,
                evidence=f"Shared IP: {', '.join(shared_ips)}"
            )

        # Check shared nameservers
        target_ns_set = set(n.lower() for n in target_ns) if isinstance(target_ns, list) else set()
        r_ns_set = set(n.lower() for n in r_ns) if isinstance(r_ns, list) else set()
        shared_ns = target_ns_set & r_ns_set
        if shared_ns:
            graph.add_edge(
                target_domain, r_domain,
                relationship="shared_ns",
                weight=0.7,
                evidence=f"Shared nameserver: {', '.join(shared_ns)}"
            )

        # Check shared SSL issuer
        if r_ssl and ssl_data.get("issuer") and r_ssl.lower() == ssl_data["issuer"].lower():
            graph.add_edge(
                target_domain, r_domain,
                relationship="shared_ssl",
                weight=0.5,
                evidence=f"Shared SSL issuer: {r_ssl}"
            )

        # Check WHOIS registrar match
        r_registrar = related.get("registrar", "")
        if r_registrar and whois_data.get("registrar") and r_registrar.lower() == whois_data["registrar"].lower():
            graph.add_edge(
                target_domain, r_domain,
                relationship="whois_match",
                weight=0.3,
                evidence=f"Shared registrar: {r_registrar}"
            )

    return graph


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def analyze_domain_graph(
    target_domain: str,
    dns_data: dict[str, Any] = None,
    whois_data: dict[str, Any] = None,
    ssl_data: dict[str, Any] = None,
    related_domains: list[dict[str, Any]] = None,
    ct_subdomains: list[str] = None,
) -> dict[str, Any]:
    """
    Perform graph-based domain relationship analysis.
    
    Returns dict with:
    - graph_features: ML-ready feature vector
    - clusters: Infrastructure clusters
    - suspicious_paths: Paths through the relationship graph
    - domain_risks: Per-domain risk scores
    - findings: Analysis findings
    - score: Overall graph risk score 0-100
    """
    try:
        graph = build_domain_graph(
            target_domain=target_domain,
            dns_data=dns_data,
            whois_data=whois_data,
            ssl_data=ssl_data,
            related_domains=related_domains,
            ct_subdomains=ct_subdomains,
        )

        # Extract features
        graph_features = _extract_graph_features(graph)

        # Detect clusters
        clusters = graph.detect_clusters()
        assessed_clusters = [_assess_cluster_risk(c) for c in clusters]

        # Find suspicious paths (paths of length > 3 between nodes)
        suspicious_paths = []
        if len(graph.nodes) > 2:
            domains_list = list(graph.nodes.keys())
            for i in range(len(domains_list)):
                for j in range(i + 1, min(i + 5, len(domains_list))):
                    paths = graph.find_paths(domains_list[i], domains_list[j], max_depth=4)
                    for path in paths:
                        if len(path) > 3:
                            suspicious_paths.append(path)

        # Domain risk scores
        domain_risks = {}
        centrality = graph.compute_centrality()
        for domain, cent in centrality.items():
            base_risk = cent * 40
            # Boost risk for domains in high-risk clusters
            for cluster in assessed_clusters:
                if domain in cluster.domains and cluster.risk_level in ("high", "critical"):
                    base_risk += 30
            domain_risks[domain] = min(int(base_risk), 100)

        # Overall findings
        findings = []
        if graph_features["cluster_count"] > 0:
            findings.append(f"Identified {graph_features['cluster_count']} infrastructure cluster(s)")
        if graph_features["shared_infrastructure_count"] > 5:
            findings.append(f"Heavy shared infrastructure detected ({graph_features['shared_infrastructure_count']} shared edges)")
        if suspicious_paths:
            findings.append(f"Found {len(suspicious_paths)} suspicious multi-hop relationship path(s)")

        # Overall score
        score = 0
        if graph_features["cluster_count"] > 3:
            score += 25
        if graph_features["shared_infrastructure_count"] > 10:
            score += 20
        if graph_features["density"] > 0.3:
            score += 15
        for cluster in assessed_clusters:
            if cluster.risk_level in ("critical", "high"):
                score += 20
        if suspicious_paths:
            score += 10

        return {
            "available": True,
            "graph_built": True,
            "node_count": graph_features["node_count"],
            "edge_count": graph_features["edge_count"],
            "graph_features": graph_features,
            "clusters": [asdict(c) for c in assessed_clusters],
            "suspicious_paths": [p[:10] for p in suspicious_paths[:5]],  # limit output
            "domain_risks": domain_risks,
            "findings": findings,
            "networkx_available": _NETWORKX_AVAILABLE,
            "score": min(score, 100),
        }

    except Exception as e:
        logger.warning("Graph analysis failed: %s", e)
        return {
            "available": False,
            "error": str(e),
            "score": 0,
        }
