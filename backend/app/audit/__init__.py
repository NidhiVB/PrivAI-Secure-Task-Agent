"""Privacy audit package for PrivAI."""

from backend.app.audit.service import AuditService, get_audit_service, set_audit_service
from backend.app.audit.merkle import compute_merkle_root, verify_merkle_inclusion_proof, generate_inclusion_proof
from backend.app.audit.anchors import BaseAuditAnchorAdapter, MockAuditAnchorAdapter, ProductionAuditAnchorAdapter

__all__ = [
    "AuditService",
    "get_audit_service",
    "set_audit_service",
    "compute_merkle_root",
    "generate_inclusion_proof",
    "verify_merkle_inclusion_proof",
    "BaseAuditAnchorAdapter",
    "MockAuditAnchorAdapter",
    "ProductionAuditAnchorAdapter",
]


