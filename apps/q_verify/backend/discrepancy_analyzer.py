"""
Q-Verify Discrepancy & Authenticity Scoring Engine
Applies digital forensic rules to detect document backdating, photo manipulation, and metadata tampering.
"""

from datetime import UTC, datetime, timedelta

from .models_data import AnomalyFlag, ParsedMetadata, VerificationResult


class DiscrepancyAnalyzer:
    """
    Forensic analysis engine that detects metadata discrepancies, software generator signatures,
    and structural PDF tampering to compute a 0-100 authenticity score.
    """

    SUSPICIOUS_SOFTWARE_SIGNATURES = {
        # Image Manipulation Tools
        "photoshop": (
            "Adobe Photoshop",
            "CRITICAL",
            35,
            "Document was edited or created using photo editing software (Adobe Photoshop).",
        ),
        "canva": (
            "Canva Online Editor",
            "HIGH",
            30,
            "Document was assembled using Canva design software instead of native financial billing or accounting systems.",
        ),
        "gimp": (
            "GIMP Image Editor",
            "CRITICAL",
            35,
            "Document was edited using open-source raster graphics editor GIMP.",
        ),
        "pixelmator": (
            "Pixelmator",
            "HIGH",
            30,
            "Document created with Pixelmator graphic manipulation suite.",
        ),
        "snapseed": ("Snapseed", "HIGH", 30, "Image edited using mobile photo enhancer Snapseed."),
        # Online / Third-Party PDF Modifiers
        "ilovepdf": (
            "iLovePDF",
            "HIGH",
            25,
            "Document processed through online consumer PDF converter iLovePDF.",
        ),
        "smallpdf": ("Smallpdf", "HIGH", 25, "Document modified using Smallpdf online utility."),
        "sejda": (
            "Sejda PDF Editor",
            "HIGH",
            25,
            "Document manipulated using Sejda online PDF modifier.",
        ),
        "pdf24": ("PDF24 Creator", "MEDIUM", 15, "Document assembled using PDF24 virtual printer."),
        "sodapdf": ("Soda PDF", "MEDIUM", 15, "Document edited using Soda PDF modifier."),
        "pdf candy": ("PDF Candy", "HIGH", 25, "Document converted or altered with PDF Candy."),
    }

    @classmethod
    def analyze(cls, metadata: ParsedMetadata) -> VerificationResult:
        anomalies: list[AnomalyFlag] = []
        now = datetime.now(UTC)

        has_timestamp_anomaly = False
        has_software_anomaly = False
        has_structural_anomaly = False

        score = 100

        # 1. Timestamp Discrepancy Rules
        if metadata.meta_created_at and metadata.meta_modified_at:
            # Modified timestamp earlier than Creation timestamp
            if metadata.meta_modified_at < (metadata.meta_created_at - timedelta(seconds=60)):
                has_timestamp_anomaly = True
                flag = AnomalyFlag(
                    code="MODIFIED_BEFORE_CREATED",
                    title="Timestamp Inversion (Mod < Create)",
                    severity="CRITICAL",
                    description=(
                        f"Embedded modification date ({metadata.meta_modified_at.strftime('%Y-%m-%d %H:%M:%S UTC')}) "
                        f"is earlier than creation date ({metadata.meta_created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}). "
                        "Indicates manual timestamp alteration or backdated metadata injection."
                    ),
                    penalty=35,
                )
                anomalies.append(flag)
                score -= flag.penalty

            # Future timestamps (> 24 hours in the future)
            if metadata.meta_created_at > (now + timedelta(days=1)) or metadata.meta_modified_at > (
                now + timedelta(days=1)
            ):
                has_timestamp_anomaly = True
                flag = AnomalyFlag(
                    code="FUTURE_TIMESTAMP",
                    title="Anomalous Future Timestamp",
                    severity="CRITICAL",
                    description="Embedded document timestamp is set in the future relative to forensic system time.",
                    penalty=30,
                )
                anomalies.append(flag)
                score -= flag.penalty

            # Extreme modification gap (> 180 days between creation and last modification)
            gap = abs((metadata.meta_modified_at - metadata.meta_created_at).days)
            if gap > 180:
                has_timestamp_anomaly = True
                flag = AnomalyFlag(
                    code="EXTENDED_TIME_GAP",
                    title=f"Significant Revision Gap ({gap} Days)",
                    severity="MEDIUM",
                    description=f"There is an extended gap of {gap} days between creation and last modification.",
                    penalty=15,
                )
                anomalies.append(flag)
                score -= flag.penalty

        # 2. File System vs Metadata Time Discrepancy (if filesystem dates available)
        if metadata.file_created_at and metadata.meta_created_at:
            fs_gap = (metadata.file_created_at - metadata.meta_created_at).days
            if abs(fs_gap) > 365:
                has_timestamp_anomaly = True
                flag = AnomalyFlag(
                    code="FS_META_DISCREPANCY",
                    title=f"Filesystem vs Embedded Date Mismatch ({abs(fs_gap)} Days)",
                    severity="MEDIUM",
                    description=(
                        f"Filesystem date ({metadata.file_created_at.strftime('%Y-%m-%d')}) differs by "
                        f"{abs(fs_gap)} days from embedded metadata date ({metadata.meta_created_at.strftime('%Y-%m-%d')})."
                    ),
                    penalty=15,
                )
                anomalies.append(flag)
                score -= flag.penalty

        # 3. Software Generator Profiling
        software_blob = (
            f"{metadata.meta_software} {metadata.meta_producer} {metadata.meta_creator}".lower()
        )
        for pattern, (sw_name, sev, penalty, desc) in cls.SUSPICIOUS_SOFTWARE_SIGNATURES.items():
            if pattern in software_blob:
                has_software_anomaly = True
                flag = AnomalyFlag(
                    code=f"SUSPECT_SOFTWARE_{pattern.upper()}",
                    title=f"Suspect Generator: {sw_name}",
                    severity=sev,
                    description=desc,
                    penalty=penalty,
                )
                anomalies.append(flag)
                score -= flag.penalty

        # 4. PDF Incremental Update & Structural Tampering
        if metadata.incremental_updates_count > 0:
            has_structural_anomaly = True
            penalty = min(30, metadata.incremental_updates_count * 15)
            flag = AnomalyFlag(
                code="PDF_INCREMENTAL_UPDATES",
                title=f"PDF Multi-Revision Updates ({metadata.incremental_updates_count} Appended Trailers)",
                severity="HIGH" if metadata.incremental_updates_count > 1 else "MEDIUM",
                description=(
                    f"Document contains {metadata.incremental_updates_count} incremental update revisions. "
                    "In forensic analysis, appended PDF trailers indicate post-generation alterations, "
                    "text overlays, or overwritten signature blocks."
                ),
                penalty=penalty,
            )
            anomalies.append(flag)
            score -= flag.penalty

        # 5. Office Metadata Inconsistencies
        if (
            metadata.editing_time_minutes == 0
            and metadata.revision_number
            and metadata.revision_number not in ("1", "0", "")
        ):
            flag = AnomalyFlag(
                code="OFFICE_ZERO_EDIT_TIME",
                title="Zero Editing Time on Multi-Revision File",
                severity="LOW",
                description=(
                    f"Document shows revision #{metadata.revision_number} but reports 0 minutes total editing time. "
                    "May indicate automated template generation or stripped revision logs."
                ),
                penalty=10,
            )
            anomalies.append(flag)
            score -= flag.penalty

        # 6. Missing / Completely Sanitized Metadata Check
        if not metadata.meta_created_at and not metadata.meta_author and not metadata.meta_software:
            flag = AnomalyFlag(
                code="METADATA_STRIPPED",
                title="Stripped / Sanitized Metadata",
                severity="MEDIUM",
                description="Document contains zero embedded author, creation timestamp, or application properties.",
                penalty=25,
            )
            anomalies.append(flag)
            score -= flag.penalty

        # Final Score Normalization
        final_score = max(0, min(100, score))

        if final_score >= 80:
            risk_level = "AUTHENTIC"
            summary = "No critical tampering indicators detected. Document metadata aligns with normal creation patterns."
        elif final_score >= 50:
            risk_level = "SUSPICIOUS"
            summary = f"Detected {len(anomalies)} metadata anomalies or discrepancy flags requiring forensic investigator scrutiny."
        else:
            risk_level = "HIGH_RISK_TAMPERED"
            summary = f"High probability of post-facto modification, backdating, or non-authentic software generation ({len(anomalies)} critical flags)."

        return VerificationResult(
            metadata=metadata,
            authenticity_score=final_score,
            risk_level=risk_level,
            anomalies=anomalies,
            has_timestamp_anomaly=has_timestamp_anomaly,
            has_software_anomaly=has_software_anomaly,
            has_structural_anomaly=has_structural_anomaly,
            summary=summary,
        )
