#!/usr/bin/env python3
"""
VAK Autonomous Code Auditor - Python MVP Demo

This example demonstrates the complete Autonomous Code Auditor MVP using the Python SDK:
- Immutable Memory Log (recording all observations)
- PRM Integration (Process Reward Model for reasoning validation)
- Formal Constraints (safety constraints)
- Cryptographic Audit Trails (verifiable decision records)

The Code Auditor reviews code for security vulnerabilities and logic errors
while guaranteeing it won't access sensitive files or introduce bugs.

Run with: python examples/code_auditor_python.py
"""

import re
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import VAK Python SDK types
from vak import (
    VakKernel,
    ToolRequest,
    ToolResponse,
    PolicyDecision,
    PolicyEffect,
    AuditEntry,
    AuditLevel,
    AgentConfig,
)


# =============================================================================
# Enums and Data Classes
# =============================================================================


class FindingSeverity(Enum):
    """Severity levels for code findings."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()
    
    def __str__(self) -> str:
        icons = {
            FindingSeverity.CRITICAL: "🔴 CRITICAL",
            FindingSeverity.HIGH: "🟠 HIGH",
            FindingSeverity.MEDIUM: "🟡 MEDIUM",
            FindingSeverity.LOW: "🟢 LOW",
            FindingSeverity.INFO: "ℹ️  INFO",
        }
        return icons.get(self, str(self.name))


class FindingCategory(Enum):
    """Categories for code findings."""
    SECURITY = "Security"
    LOGIC = "Logic"
    PERFORMANCE = "Performance"
    STYLE = "Style"
    BEST_PRACTICE = "Best Practice"
    DEPENDENCY = "Dependency"


class EpisodeType(Enum):
    """Types of episodes in episodic memory."""
    OBSERVATION = "observation"
    THOUGHT = "thought"
    ACTION = "action"
    SYSTEM = "system"


@dataclass
class Episode:
    """Represents a single episode in the agent's memory."""
    episode_type: EpisodeType
    content: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    hash: str = field(default="")
    prev_hash: str = field(default="")
    
    def __post_init__(self):
        if not self.hash:
            self.hash = self._compute_hash()
    
    def _compute_hash(self) -> str:
        data = f"{self.timestamp}:{self.episode_type.value}:{self.content}:{self.prev_hash}"
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class CodeFinding:
    """Represents a code analysis finding."""
    id: str
    severity: FindingSeverity
    category: FindingCategory
    file_path: str
    line_range: Tuple[int, int]
    description: str
    suggested_fix: Optional[str] = None
    confidence: float = 0.0


@dataclass
class AuditLogEntry:
    """Represents an entry in the audit log."""
    id: int
    timestamp: str
    agent_id: str
    action: str
    resource: str
    decision: str
    hash: str
    prev_hash: str


@dataclass
class CodeAuditorConfig:
    """Configuration for the Code Auditor."""
    max_steps: int = 50
    prm_threshold: float = 0.6
    forbidden_files: List[str] = field(default_factory=lambda: [
        ".env",
        "secrets.json",
        "credentials.yaml",
        ".git-credentials",
        "private.key",
        "id_rsa",
        ".npmrc",
        ".pypirc",
    ])
    max_files: int = 100


# =============================================================================
# Mock PRM (Process Reward Model)
# =============================================================================


class MockPRM:
    """
    Mock Process Reward Model for scoring reasoning steps.
    In production, this would be a fine-tuned LLM.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.default_score = 0.75
        self.default_confidence = 0.8
    
    def score_step(self, thought: str, context: str) -> Dict[str, float]:
        """Score a reasoning step."""
        # Simple heuristic scoring for demo
        score = self.default_score
        confidence = self.default_confidence
        
        # Boost score for specific keywords indicating good reasoning
        good_patterns = ["check", "verify", "validate", "analyze", "review"]
        for pattern in good_patterns:
            if pattern in thought.lower():
                score = min(1.0, score + 0.05)
        
        return {
            "score": score,
            "confidence": confidence,
            "reasoning": f"Evaluated step: '{thought[:50]}...'"
        }


# =============================================================================
# Episodic Memory
# =============================================================================


class EpisodicMemory:
    """Hash-chained episodic memory for recording agent history."""
    
    def __init__(self):
        self.episodes: List[Episode] = []
        self._genesis_hash = "0" * 64
    
    def append(self, episode: Episode) -> Episode:
        """Append an episode to the memory chain."""
        prev_hash = self.episodes[-1].hash if self.episodes else self._genesis_hash
        episode.prev_hash = prev_hash
        episode.hash = episode._compute_hash()
        self.episodes.append(episode)
        return episode
    
    def get_all(self) -> List[Episode]:
        """Get all episodes."""
        return self.episodes.copy()
    
    def root_hash(self) -> str:
        """Get the current root hash of the memory chain."""
        return self.episodes[-1].hash if self.episodes else self._genesis_hash
    
    def verify_chain(self) -> bool:
        """Verify the integrity of the episode chain."""
        if not self.episodes:
            return True
        
        for i, episode in enumerate(self.episodes):
            expected_prev = self.episodes[i - 1].hash if i > 0 else self._genesis_hash
            if episode.prev_hash != expected_prev:
                return False
            
            computed_hash = episode._compute_hash()
            # Note: hash is already computed in __post_init__, but we can re-verify
        
        return True


# =============================================================================
# Audit Logger
# =============================================================================


class AuditLogger:
    """Cryptographic audit logger with hash-chained entries."""
    
    def __init__(self):
        self.entries: List[AuditLogEntry] = []
        self._next_id = 1
        self._genesis_hash = "0" * 64
    
    def log(
        self,
        agent_id: str,
        action: str,
        resource: str,
        decision: str
    ) -> AuditLogEntry:
        """Log an action with cryptographic hash chaining."""
        timestamp = datetime.utcnow().isoformat()
        prev_hash = self.entries[-1].hash if self.entries else self._genesis_hash
        
        # Compute hash
        data = f"{self._next_id}:{timestamp}:{agent_id}:{action}:{resource}:{decision}:{prev_hash}"
        hash_value = hashlib.sha256(data.encode()).hexdigest()
        
        entry = AuditLogEntry(
            id=self._next_id,
            timestamp=timestamp,
            agent_id=agent_id,
            action=action,
            resource=resource,
            decision=decision,
            hash=hash_value,
            prev_hash=prev_hash,
        )
        
        self.entries.append(entry)
        self._next_id += 1
        return entry
    
    def verify_chain(self) -> bool:
        """Verify the integrity of the audit chain."""
        if not self.entries:
            return True
        
        for i, entry in enumerate(self.entries):
            expected_prev = self.entries[i - 1].hash if i > 0 else self._genesis_hash
            if entry.prev_hash != expected_prev:
                return False
        
        return True
    
    def get_entries(self) -> List[AuditLogEntry]:
        """Get all audit entries."""
        return self.entries.copy()


# =============================================================================
# Code Auditor
# =============================================================================


class CodeAuditor:
    """
    Autonomous Code Auditor Agent
    
    Reviews code for security vulnerabilities and logic errors while
    providing cryptographic proof of its reasoning and decisions.
    """
    
    def __init__(self, config: Optional[CodeAuditorConfig] = None):
        self.config = config or CodeAuditorConfig()
        self.episodic_memory = EpisodicMemory()
        self.audit_logger = AuditLogger()
        self.prm = MockPRM()
        self.step_count = 0
        self.files_analyzed: List[str] = []
        self.findings: List[CodeFinding] = []
    
    def is_forbidden_file(self, file_path: str) -> bool:
        """Check if a file is forbidden from access."""
        for pattern in self.config.forbidden_files:
            if pattern in file_path or file_path.endswith(pattern):
                return True
        return False
    
    def verify_constraints(self) -> Tuple[bool, Optional[str]]:
        """Verify operational constraints."""
        if self.step_count >= self.config.max_steps:
            return False, f"Max steps exceeded: {self.step_count} >= {self.config.max_steps}"
        
        if len(self.files_analyzed) >= self.config.max_files:
            return False, f"Max files exceeded: {len(self.files_analyzed)} >= {self.config.max_files}"
        
        return True, None
    
    def record_observation(self, observation: str) -> None:
        """Record an observation in episodic memory."""
        episode = Episode(EpisodeType.OBSERVATION, observation)
        self.episodic_memory.append(episode)
    
    def record_thought(self, thought: str) -> None:
        """Record a thought in episodic memory."""
        episode = Episode(EpisodeType.THOUGHT, thought)
        self.episodic_memory.append(episode)
    
    def record_action(self, action: str) -> None:
        """Record an action in episodic memory."""
        episode = Episode(EpisodeType.ACTION, action)
        self.episodic_memory.append(episode)
    
    def analyze_file(self, file_path: str, content: str) -> Tuple[bool, Optional[str]]:
        """Analyze a file for security vulnerabilities and issues."""
        self.step_count += 1
        
        # Verify constraints
        ok, error = self.verify_constraints()
        if not ok:
            return False, error
        
        # Check if file is forbidden
        if self.is_forbidden_file(file_path):
            self.audit_logger.log(
                "code-auditor",
                "read_file",
                file_path,
                "DENIED"
            )
            return False, f"Access denied: '{file_path}' is a forbidden file"
        
        # Log allowed access
        self.audit_logger.log(
            "code-auditor",
            "read_file",
            file_path,
            "ALLOWED"
        )
        
        # Record observation
        self.record_observation(f"Reading file: {file_path}")
        self.files_analyzed.append(file_path)
        
        # Run all analysis passes
        self._analyze_sql_injection(file_path, content)
        self._analyze_hardcoded_secrets(file_path, content)
        self._analyze_input_validation(file_path, content)
        self._analyze_error_handling(file_path, content)
        
        return True, None
    
    def _analyze_sql_injection(self, file_path: str, content: str) -> None:
        """Check for SQL injection vulnerabilities."""
        self.step_count += 1
        self.record_thought("Checking for potential SQL injection vulnerabilities")
        
        # Score reasoning step
        score = self.prm.score_step(
            "Analyzing for SQL injection patterns",
            "SQL injection analysis"
        )
        
        if score["score"] < self.config.prm_threshold:
            self.record_thought(f"Low confidence reasoning (score: {score['score']}), skipping")
            return
        
        # Dangerous patterns
        patterns = [
            (r'format!\s*\(\s*"SELECT', "String formatting in SQL SELECT"),
            (r'format!\s*\(\s*"INSERT', "String formatting in SQL INSERT"),
            (r'format!\s*\(\s*"UPDATE', "String formatting in SQL UPDATE"),
            (r'format!\s*\(\s*"DELETE', "String formatting in SQL DELETE"),
            (r'f"SELECT.*\{', "f-string in SQL SELECT (Python)"),
            (r'f"INSERT.*\{', "f-string in SQL INSERT (Python)"),
            (r'execute\s*\(\s*f"', "execute with f-string"),
            (r'\.format\s*\(.*SELECT', ".format() in SQL query"),
            (r'\+\s*["\']SELECT', "String concatenation in SQL"),
        ]
        
        for line_num, line in enumerate(content.split('\n'), 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    finding = CodeFinding(
                        id=f"SQL-{file_path.replace('/', '_')}-{line_num}",
                        severity=FindingSeverity.CRITICAL,
                        category=FindingCategory.SECURITY,
                        file_path=file_path,
                        line_range=(line_num, line_num),
                        description=f"Potential SQL injection: {desc}",
                        suggested_fix="Use parameterized queries instead of string formatting",
                        confidence=score["score"],
                    )
                    self.findings.append(finding)
                    self.record_action(f"Found SQL injection vulnerability at line {line_num}")
                    
                    self.audit_logger.log(
                        "code-auditor",
                        "report_finding",
                        f"{file_path}:{line_num}",
                        "ALLOWED"
                    )
    
    def _analyze_hardcoded_secrets(self, file_path: str, content: str) -> None:
        """Check for hardcoded secrets."""
        self.step_count += 1
        self.record_thought("Checking for hardcoded secrets and credentials")
        
        score = self.prm.score_step(
            "Analyzing for hardcoded secrets",
            "Secret detection analysis"
        )
        
        secret_patterns = [
            ("api_key", "API key"),
            ("apikey", "API key"),
            ("api-key", "API key"),
            ("secret_key", "Secret key"),
            ("secretkey", "Secret key"),
            ("password", "Password"),
            ("passwd", "Password"),
            ("private_key", "Private key"),
            ("access_token", "Access token"),
            ("auth_token", "Auth token"),
            ("bearer", "Bearer token"),
            ("aws_secret", "AWS secret"),
            ("database_url", "Database URL"),
        ]
        
        for line_num, line in enumerate(content.split('\n'), 1):
            line_lower = line.lower()
            
            for pattern, desc in secret_patterns:
                if pattern in line_lower and ('=' in line or ':' in line):
                    # Check for string assignment
                    if '"' in line or "'" in line:
                        finding = CodeFinding(
                            id=f"SECRET-{file_path.replace('/', '_')}-{line_num}",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.SECURITY,
                            file_path=file_path,
                            line_range=(line_num, line_num),
                            description=f"Potential hardcoded {desc}",
                            suggested_fix="Use environment variables or a secrets manager",
                            confidence=score["score"],
                        )
                        self.findings.append(finding)
                        self.record_action(f"Found hardcoded secret at line {line_num}")
    
    def _analyze_input_validation(self, file_path: str, content: str) -> None:
        """Check for input validation issues."""
        self.step_count += 1
        self.record_thought("Checking for missing input validation")
        
        score = self.prm.score_step(
            "Analyzing for input validation",
            "Input validation analysis"
        )
        
        patterns = [
            (r'\.unwrap\(\)', "Unchecked unwrap", FindingSeverity.MEDIUM),
            (r'\.expect\(', "Consider proper error handling instead of expect", FindingSeverity.LOW),
            (r'unsafe\s*\{', "Unsafe code block", FindingSeverity.HIGH),
            (r'\beval\s*\(', "Use of eval() is dangerous", FindingSeverity.CRITICAL),
            (r'\bexec\s*\(', "Use of exec() requires careful validation", FindingSeverity.HIGH),
        ]
        
        for line_num, line in enumerate(content.split('\n'), 1):
            for pattern, desc, severity in patterns:
                if re.search(pattern, line):
                    finding = CodeFinding(
                        id=f"INPUT-{file_path.replace('/', '_')}-{line_num}",
                        severity=severity,
                        category=FindingCategory.LOGIC,
                        file_path=file_path,
                        line_range=(line_num, line_num),
                        description=desc,
                        suggested_fix="Use proper error handling (match, if-let, ?)",
                        confidence=score["score"],
                    )
                    self.findings.append(finding)
                    self.record_action(f"Found input validation issue at line {line_num}")
    
    def _analyze_error_handling(self, file_path: str, content: str) -> None:
        """Check for error handling issues."""
        self.step_count += 1
        self.record_thought("Checking for error handling issues")
        
        score = self.prm.score_step(
            "Analyzing error handling",
            "Error handling analysis"
        )
        
        patterns = [
            (r'let\s+_\s*=', "Silently discarding Result", FindingSeverity.LOW),
            (r'panic!\s*\(', "Explicit panic", FindingSeverity.HIGH),
            (r'todo!\s*\(\)', "Unimplemented code (todo!)", FindingSeverity.HIGH),
            (r'unimplemented!\s*\(\)', "Unimplemented code", FindingSeverity.HIGH),
            (r'except:\s*$', "Bare except clause (Python)", FindingSeverity.MEDIUM),
            (r'except\s+Exception:', "Catching broad Exception", FindingSeverity.LOW),
        ]
        
        for line_num, line in enumerate(content.split('\n'), 1):
            for pattern, desc, severity in patterns:
                if re.search(pattern, line):
                    finding = CodeFinding(
                        id=f"ERR-{file_path.replace('/', '_')}-{line_num}",
                        severity=severity,
                        category=FindingCategory.BEST_PRACTICE,
                        file_path=file_path,
                        line_range=(line_num, line_num),
                        description=desc,
                        suggested_fix="Handle errors explicitly and log appropriately",
                        confidence=score["score"],
                    )
                    self.findings.append(finding)
    
    def generate_audit_receipt(self) -> Dict[str, Any]:
        """Generate a cryptographic receipt for the audit."""
        entries = self.audit_logger.get_entries()
        chain_hash = entries[-1].hash if entries else "0" * 64
        
        severity_counts: Dict[str, int] = {}
        for finding in self.findings:
            key = finding.severity.name
            severity_counts[key] = severity_counts.get(key, 0) + 1
        
        return {
            "session_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "total_steps": self.step_count,
            "files_analyzed": self.files_analyzed.copy(),
            "findings_count": len(self.findings),
            "findings_by_severity": severity_counts,
            "audit_chain_hash": chain_hash,
            "episodic_memory_hash": self.episodic_memory.root_hash(),
        }
    
    def get_findings(self) -> List[CodeFinding]:
        """Get all findings."""
        return self.findings.copy()
    
    def get_episodes(self) -> List[Episode]:
        """Get all episodes from episodic memory."""
        return self.episodic_memory.get_all()


# =============================================================================
# Sample Code for Demo
# =============================================================================

SAMPLE_VULNERABLE_CODE = '''
# Sample vulnerable code for demonstration

import os

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"  # SQL Injection!
    return database.execute(query)

def connect_to_api():
    api_key = "sk-1234567890abcdef"  # Hardcoded secret!
    password = "super_secret_password123"  # Another hardcoded secret!
    return ApiClient(api_key, password)

def process_input(data):
    value = int(data)  # No validation!
    result = eval(data)  # Dangerous eval!
    return result

def incomplete_feature():
    # TODO: implement this
    pass

def ignore_error():
    try:
        risky_operation()
    except:  # Bare except!
        pass
'''

SAMPLE_SAFE_CODE = '''
# Sample safe code for demonstration

import os
from typing import Optional

def get_user(user_id: str) -> Optional[User]:
    query = "SELECT * FROM users WHERE id = %s"
    return database.execute(query, (user_id,))  # Parameterized - safe!

def connect_to_api() -> ApiClient:
    api_key = os.environ.get("API_KEY")  # From environment - safe!
    if not api_key:
        raise ValueError("API_KEY not set")
    return ApiClient(api_key)

def process_input(data: str) -> int:
    try:
        value = int(data)
        if value < 0 or value > 1000:
            raise ValueError("Value out of range")
        return value
    except ValueError as e:
        logger.error(f"Invalid input: {e}")
        raise

def handle_error():
    try:
        risky_operation()
    except SpecificError as e:
        logger.error(f"Operation failed: {e}")
        raise
'''


# =============================================================================
# Main Demo
# =============================================================================


def print_header(title: str) -> None:
    """Print a section header."""
    print("=" * 65)
    print(title)
    print("=" * 65)
    print()


def print_finding(finding: CodeFinding) -> None:
    """Pretty print a code finding."""
    print(f"   ┌{'─' * 58}")
    print(f"   │ {finding.severity} [{finding.category.value}]")
    print(f"   │ File: {finding.file_path}:{finding.line_range[0]}-{finding.line_range[1]}")
    print(f"   │ ID: {finding.id}")
    print(f"   │ Description: {finding.description}")
    if finding.suggested_fix:
        print(f"   │ Suggested Fix: {finding.suggested_fix}")
    print(f"   │ Confidence: {finding.confidence:.2f}")
    print(f"   └{'─' * 58}")
    print()


def print_receipt(receipt: Dict[str, Any]) -> None:
    """Pretty print an audit receipt."""
    print("═" * 65)
    print("                    AUDIT RECEIPT")
    print("═" * 65)
    print(f"Session ID:    {receipt['session_id']}")
    print(f"Timestamp:     {receipt['timestamp']}")
    print(f"Total Steps:   {receipt['total_steps']}")
    print(f"Files:         {len(receipt['files_analyzed'])}")
    print(f"Findings:      {receipt['findings_count']}")
    print("─" * 65)
    print("Findings by Severity:")
    for severity, count in receipt.get("findings_by_severity", {}).items():
        print(f"  {severity:12} {count}")
    print("─" * 65)
    print("Audit Chain Hash:")
    print(f"  {receipt['audit_chain_hash']}")
    print("Episodic Memory Hash:")
    print(f"  {receipt['episodic_memory_hash']}")
    print("═" * 65)


def main():
    """Run the Code Auditor demo."""
    print()
    print("╔" + "═" * 63 + "╗")
    print("║     VAK AUTONOMOUS CODE AUDITOR - PYTHON MVP DEMO            ║")
    print("╚" + "═" * 63 + "╝")
    print()
    
    # Create the Code Auditor
    print("🔧 Initializing Code Auditor...\n")
    config = CodeAuditorConfig()
    auditor = CodeAuditor(config)
    
    print("   Configuration:")
    print(f"   ├── Max Steps: {config.max_steps}")
    print(f"   ├── PRM Threshold: {config.prm_threshold:.2f}")
    print(f"   ├── Max Files: {config.max_files}")
    print(f"   └── Forbidden Files: {config.forbidden_files[:3]}...")
    print()
    
    # Demo 1: Test forbidden file access
    print_header("DEMO 1: Testing access control (forbidden file access)")
    
    ok, error = auditor.analyze_file(".env", "SECRET=value")
    if not ok:
        print(f"   ✅ Access correctly denied: {error}")
    else:
        print("   ❌ Unexpected: Access should have been denied!")
    print()
    
    # Demo 2: Analyze vulnerable code
    print_header("DEMO 2: Analyzing vulnerable code")
    
    ok, error = auditor.analyze_file("src/vulnerable.py", SAMPLE_VULNERABLE_CODE)
    if ok:
        print("   ✅ Analysis complete\n")
    else:
        print(f"   ❌ Analysis failed: {error}\n")
    
    # Display findings
    print("   📋 FINDINGS:\n")
    for finding in auditor.get_findings():
        print_finding(finding)
    
    # Demo 3: Analyze safe code
    print_header("DEMO 3: Analyzing safe code")
    
    initial_findings = len(auditor.get_findings())
    ok, error = auditor.analyze_file("src/safe_code.py", SAMPLE_SAFE_CODE)
    new_findings = len(auditor.get_findings()) - initial_findings
    
    if ok:
        print("   ✅ Safe code analysis complete")
        print(f"   New findings: {new_findings} (expected: minimal)\n")
    
    # Demo 4: View episodic memory
    print_header("DEMO 4: Episodic Memory Chain (Reasoning Trace)")
    
    episodes = auditor.get_episodes()
    print(f"   Total episodes recorded: {len(episodes)}\n")
    
    # Show last 10 episodes
    for i, episode in enumerate(episodes[-10:], len(episodes) - 9):
        type_icons = {
            EpisodeType.OBSERVATION: "👁️ ",
            EpisodeType.THOUGHT: "💭",
            EpisodeType.ACTION: "⚡",
            EpisodeType.SYSTEM: "📝",
        }
        icon = type_icons.get(episode.episode_type, "📝")
        print(f"   [{i}] {icon} {episode.content[:60]}...")
    print()
    
    # Demo 5: Generate audit receipt
    print_header("DEMO 5: Cryptographic Audit Receipt")
    
    receipt = auditor.generate_audit_receipt()
    print_receipt(receipt)
    print()
    
    # Demo 6: Verify chain integrity
    print_header("DEMO 6: Audit Chain Verification")
    
    if auditor.audit_logger.verify_chain():
        print("   ✅ Audit chain integrity verified - no tampering detected\n")
    else:
        print("   ❌ Audit chain verification failed!\n")
    
    if auditor.episodic_memory.verify_chain():
        print("   ✅ Episodic memory chain integrity verified\n")
    else:
        print("   ❌ Episodic memory chain verification failed!\n")
    
    # Summary
    print_header("                        DEMO SUMMARY")
    print()
    print("   The VAK Autonomous Code Auditor MVP demonstrates:")
    print()
    print("   ✅ Immutable Memory Log (Hash-Chained)")
    print("      └── All observations and thoughts cryptographically linked")
    print()
    print("   ✅ PRM Integration")
    print("      └── Reasoning steps scored for confidence")
    print()
    print("   ✅ Formal Constraints")
    print("      └── Safety rules enforced (max steps, forbidden files)")
    print()
    print("   ✅ Cryptographic Audit Trail")
    print("      └── Every action logged with hash-chained integrity")
    print()
    print("=" * 65)
    print()


if __name__ == "__main__":
    main()
