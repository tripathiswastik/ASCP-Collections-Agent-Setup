"""Drain Log Parsing Engine for Oracle ASCP Collections.
Implements the fixed-depth parse tree algorithm (Drain) to tokenize unstructured
concurrent request logs and trace dumps into structured log templates and parameter vectors.
"""

import re
from typing import List, Dict, Any, Optional, Tuple

class Node:
    """Node in the Drain prefix tree."""
    def __init__(self, depth: int = 1, digit_or_token: Optional[str] = None):
        self.depth = depth
        self.digit_or_token = digit_or_token
        self.children: Dict[str, 'Node'] = {}
        self.log_clusters: List['LogCluster'] = []

class LogCluster:
    """A cluster of log messages sharing the same template."""
    def __init__(self, log_template_tokens: List[str], log_id: int):
        self.log_template_tokens = log_template_tokens
        self.log_id = log_id
        self.size = 1

    @property
    def template_str(self) -> str:
        return " ".join(self.log_template_tokens)

class DrainLogParser:
    """Fixed-depth Parse Tree Log Parser (Drain) optimized for Oracle EBS logs."""

    TIMESTAMP_PATTERNS = [
        re.compile(r"^\d{2}-[A-Z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}$"),
        re.compile(r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"),
        re.compile(r"^\d{2}:\d{2}:\d{2}$")
    ]

    ORACLE_OBJECT_PATTERN = re.compile(r"^(MSC|MLOG\$|APPLSYS|APPS|BOM|INV|WIP|MRP|FND)_[A-Z0-9_\$]+$", re.IGNORECASE)
    DIGIT_PATTERN = re.compile(r"^\d+$")
    ERROR_CODE_PATTERN = re.compile(r"^ORA-\d{5}:?$", re.IGNORECASE)
    MEM_ADDR_PATTERN = re.compile(r"^0x[0-9a-fA-F]+:?$")
    THREAD_ID_PATTERN = re.compile(r"^(?:tid=\d+|thread[_-]\d+|worker[_-]\d+|pid[_-]\d+)$", re.IGNORECASE)

    TS_BRACKET_PATTERN = re.compile(r"\[(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]")
    SID_SEARCH_PATTERN = re.compile(r"SID\s+(\d+)", re.IGNORECASE)
    MEM_HEX_FIND_PATTERN = re.compile(r"0x[0-9a-fA-F]+")
    TID_SUB_PATTERN = re.compile(r"\btid=\d+\b", re.IGNORECASE)
    THREAD_SUB_PATTERN = re.compile(r"\bThread-\d+\b", re.IGNORECASE)

    def __init__(
        self,
        depth: int = 4,
        similarity_threshold: float = 0.5,
        max_children: int = 100,
        param_token: str = "<*>",
        max_clusters: int = 500,
        max_leaf_clusters: int = 20
    ):
        self.depth = depth  # Max depth of prefix tree
        self.similarity_threshold = similarity_threshold
        self.max_children = max_children
        self.param_token = param_token
        self.max_clusters = max_clusters
        self.max_leaf_clusters = max_leaf_clusters
        self.root_node = Node(depth=1)
        self.clusters: List[LogCluster] = []

    def _preprocess_tokens(self, line: str) -> Tuple[List[str], Dict[str, Any]]:
        """Normalize line and extract recognized domain variables while preserving critical ORA codes."""
        params: Dict[str, Any] = {"TARGET_OBJECTS": []}
        
        # 1. Extract bracketed timestamps e.g. [12-OCT-2025 04:12:01]
        ts_match = self.TS_BRACKET_PATTERN.search(line)
        if ts_match:
            params["TIMESTAMP"] = ts_match.group(1)
            line = line.replace(f"[{ts_match.group(1)}]", "[<TIMESTAMP>]")

        # 2. Extract SID/SERIAL e.g. (SID 412, SERIAL# 28419)
        sid_match = self.SID_SEARCH_PATTERN.search(line)
        if sid_match:
            params["SID"] = int(sid_match.group(1))

        # 3. Mask memory addresses e.g. at 0x7fff89ab10cd
        mem_match = self.MEM_HEX_FIND_PATTERN.findall(line)
        if mem_match:
            params["MEM_ADDRESSES"] = mem_match
            for addr in mem_match:
                line = line.replace(addr, "<MEM_ADDR>")

        # 4. Mask worker thread/PID indicators e.g. tid=8924 or Thread-12
        line = self.TID_SUB_PATTERN.sub("<THREAD_ID>", line)
        line = self.THREAD_SUB_PATTERN.sub("<THREAD_ID>", line)

        tokens = line.strip().split()
        normalized_tokens = []

        for token in tokens:
            clean = token.strip("(),;\"'.:")
            # Fast-path checks before regex evaluations
            if clean.startswith("ORA-") or self.ERROR_CODE_PATTERN.match(clean):
                normalized_tokens.append(token)
            elif clean.startswith("0x") or clean == "<MEM_ADDR>" or self.MEM_ADDR_PATTERN.match(clean):
                normalized_tokens.append("<MEM_ADDR>")
            elif clean == "<THREAD_ID>" or self.THREAD_ID_PATTERN.match(clean):
                normalized_tokens.append("<THREAD_ID>")
            elif clean.startswith(("MSC_", "MLOG$", "APPLSYS_", "APPS_", "BOM_", "INV_", "WIP_", "MRP_", "FND_")) or self.ORACLE_OBJECT_PATTERN.match(clean):
                params["TARGET_OBJECTS"].append(clean)
                normalized_tokens.append("<TARGET_OBJECT>")
            elif (clean.isdigit() or self.DIGIT_PATTERN.match(clean)) and token != "[<TIMESTAMP>]":
                normalized_tokens.append("<NUM>")
            else:
                normalized_tokens.append(token)

        return normalized_tokens, params

    def _tree_search(self, root: Node, tokens: List[str]) -> Optional[LogCluster]:
        """Traverse fixed-depth parse tree to locate matching cluster candidate."""
        seq_len = len(tokens)
        if seq_len == 0:
            return None

        # Level 1: Length token
        len_str = str(seq_len)
        if len_str not in root.children:
            return None
        curr_node = root.children[len_str]

        # Level 2..(depth-1): First tokens
        current_depth = 2
        while current_depth < self.depth:
            token_idx = current_depth - 2
            if token_idx >= seq_len:
                break

            token = tokens[token_idx]
            if token in curr_node.children:
                curr_node = curr_node.children[token]
            elif self.param_token in curr_node.children:
                curr_node = curr_node.children[self.param_token]
            else:
                return None
            current_depth += 1

        # Search leaf cluster list for best similarity match
        best_cluster: Optional[LogCluster] = None
        best_sim = -1.0

        for cluster in curr_node.log_clusters:
            sim = self._calculate_similarity(cluster.log_template_tokens, tokens)
            if sim > best_sim and sim >= self.similarity_threshold:
                best_sim = sim
                best_cluster = cluster

        return best_cluster

    def _calculate_similarity(self, template_tokens: List[str], tokens: List[str]) -> float:
        """Sequence similarity metric between cluster template and incoming tokens with early short-circuit."""
        n = len(tokens)
        if len(template_tokens) != n or n == 0:
            return 0.0

        needed_matches = int(n * self.similarity_threshold)
        matches = 0
        remaining = n

        for t1, t2 in zip(template_tokens, tokens):
            if t1 == self.param_token or t1 == t2:
                matches += 1
            if (matches + remaining) < needed_matches:
                # Early short-circuit: impossible to achieve required similarity
                return 0.0
            remaining -= 1

        return matches / float(n)

    def _add_to_tree(self, root: Node, cluster: LogCluster, tokens: List[str]):
        """Insert new cluster into the prefix tree with bounded leaf cluster size."""
        seq_len = len(tokens)
        len_str = str(seq_len)

        if len_str not in root.children:
            root.children[len_str] = Node(depth=2, digit_or_token=len_str)
        curr_node = root.children[len_str]

        current_depth = 2
        while current_depth < self.depth:
            token_idx = current_depth - 2
            if token_idx >= seq_len:
                break

            token = tokens[token_idx]
            # If token contains digits or is a variable token, use wildcard
            if any(char.isdigit() for char in token) or token.startswith("<"):
                node_token = self.param_token
            else:
                node_token = token

            if node_token not in curr_node.children:
                if len(curr_node.children) >= self.max_children:
                    node_token = self.param_token
                if node_token not in curr_node.children:
                    curr_node.children[node_token] = Node(depth=current_depth + 1, digit_or_token=node_token)

            curr_node = curr_node.children[node_token]
            current_depth += 1

        # Bound leaf clusters to prevent linear comparison blowup
        if len(curr_node.log_clusters) >= self.max_leaf_clusters:
            curr_node.log_clusters.sort(key=lambda c: c.size, reverse=True)
            curr_node.log_clusters.pop()

        curr_node.log_clusters.append(cluster)

    def parse_line(self, line: str) -> Dict[str, Any]:
        """Parse a single raw log line into structured template & parameters with cluster capacity cap."""
        raw_line = line.strip()
        if not raw_line:
            return {"raw": "", "template": "", "parameters": {}, "cluster_id": -1}

        tokens, extracted_params = self._preprocess_tokens(raw_line)
        match = self._tree_search(self.root_node, tokens)

        if match is None:
            # Respect global cluster capacity cap
            if len(self.clusters) >= self.max_clusters:
                min_cluster = min(self.clusters, key=lambda c: c.size)
                self.clusters.remove(min_cluster)

            new_id = len(self.clusters) + 1
            cluster = LogCluster(tokens, new_id)
            self.clusters.append(cluster)
            self._add_to_tree(self.root_node, cluster, tokens)
            template_tokens = tokens
        else:
            # Update existing cluster template with wildcard where tokens diverge
            match.size += 1
            updated_tokens = []
            for t1, t2 in zip(match.log_template_tokens, tokens):
                if t1 == t2:
                    updated_tokens.append(t1)
                else:
                    updated_tokens.append(self.param_token)
            match.log_template_tokens = updated_tokens
            template_tokens = match.log_template_tokens

        # Derive parameter vector by aligning raw tokens against template tokens
        raw_tokens = raw_line.split()
        for i in range(min(len(raw_tokens), len(template_tokens))):
            tmpl = template_tokens[i]
            val = raw_tokens[i]
            if tmpl.startswith("<") and tmpl.endswith(">") and tmpl != "[<TIMESTAMP>]":
                clean_key = tmpl.strip("<>").replace("*", f"PARAM_{i}")
                extracted_params.setdefault(clean_key, val)

        template_str = " ".join(template_tokens)
        return {
            "raw": raw_line,
            "template": template_str,
            "parameters": extracted_params,
            "cluster_id": match.log_id if match else len(self.clusters)
        }

    def parse_log_stream(self, lines, max_lines: Optional[int] = None):
        """Generator yielding parsed lines to avoid massive memory allocations."""
        count = 0
        for line in lines:
            line_str = line.strip() if isinstance(line, str) else str(line).strip()
            if line_str:
                if max_lines and count >= max_lines:
                    break
                yield self.parse_line(line_str)
                count += 1

    def parse_log_text(self, log_content: str, max_lines: Optional[int] = None) -> List[Dict[str, Any]]:
        """Parse multi-line log or trace dump with optional line cap."""
        if not log_content:
            return []
        lines = [line.strip() for line in log_content.splitlines() if line.strip()]
        if max_lines and len(lines) > max_lines:
            lines = lines[-max_lines:]
        return list(self.parse_log_stream(lines, max_lines=max_lines))

    def parse_file(self, filepath: str, max_lines: Optional[int] = None) -> List[Dict[str, Any]]:
        """Standardized file parser routing file contents directly through parse_log_text."""
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return self.parse_log_text(f.read(), max_lines=max_lines)
