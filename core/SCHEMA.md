# `core` — Database Schema & ERD Specifications

> [!TIP]
> **dbdiagram.io Compatibility:** Copy and paste the DBML code below directly into [dbdiagram.io](https://dbdiagram.io) to generate visual Entity-Relationship diagrams.

---

## 1. DBML (Database Markup Language for dbdiagram.io)

```dbml
// ==========================================
// ForensiQ Core Base Entity Model Schema
// dbdiagram.io specification
// ==========================================

Table forensic_base_model {
  id uuid [pk, note: 'UUID v4 Primary Key']
  created_at timestamp [default: `now()`, note: 'Ingestion timestamp']
  updated_at timestamp [default: `now()`, note: 'Last modification']
}

Table investigation_profiles {
  id uuid [pk, note: 'UUID v4 Primary Key']
  full_name varchar(255) [not null, note: 'Target / Auditee Full Name']
  employee_id varchar(64) [default: '', note: 'Employee ID or Case Reference']
  department varchar(128) [default: '', note: 'Department / Division']
  designation varchar(128) [default: '', note: 'Designation / Position']
  email varchar(254) [default: '']
  phone varchar(32) [default: '']
  status varchar(20) [default: 'ACTIVE', note: 'ACTIVE, MONITORING, CLEARED, FLAGGED']
  risk_level varchar(20) [default: 'MEDIUM', note: 'LOW, MEDIUM, HIGH, CRITICAL']
  notes text [default: '']
  avatar_color varchar(32) [default: 'indigo']
  keywords json [note: 'Search/investigation keywords array']
  created_at timestamp [default: `now()`]
  updated_at timestamp [default: `now()`]
}

Table audits {
  id uuid [pk, note: 'UUID v4 Primary Key']
  name varchar(32) [unique, not null, note: 'Auto-generated ID: YYYY-WB-XX']
  title varchar(255) [default: '', note: 'Audit Title / Objective']
  description text [default: '', note: 'Investigation scope / allegations']
  status varchar(20) [default: 'ACTIVE', note: 'ACTIVE, IN_PROGRESS, COMPLETED, ARCHIVED']
  created_at timestamp [default: `now()`]
  updated_at timestamp [default: `now()`]
}

Table audit_profiles {
  id int [pk, increment]
  audit_id uuid [ref: > audits.id, note: 'Foreign Key to Audit']
  investigationprofile_id uuid [ref: > investigation_profiles.id, note: 'Foreign Key to InvestigationProfile']
}
```

---

## 2. Django Abstract ORM Models

```python
import uuid
from django.db import models


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class UUIDModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class ForensicBaseModel(UUIDModel, TimeStampedModel):
    class Meta:
        abstract = True


class Audit(ForensicBaseModel):
    name = models.CharField(max_length=32, unique=True, db_index=True)
    title = models.CharField(max_length=255, blank=True, default="")
    description = models.TextField(blank=True, default="")
    status = models.CharField(max_length=20, default="ACTIVE")
    profiles = models.ManyToManyField("InvestigationProfile", related_name="audits", blank=True)
```
