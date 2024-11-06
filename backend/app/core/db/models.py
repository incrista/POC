from datetime import datetime
from typing import Optional, List
from uuid import UUID
from sqlmodel import SQLModel, Field
from sqlalchemy import Column, DateTime, UniqueConstraint, Index, Text, ARRAY, JSON, Double, Integer
from pydantic import Json

# Enums
from enum import Enum

# Enums
class CNEntity(str, Enum):
    CNPL = "CNPL"
    CNFZC = "CNFZC"
    CNLLC = "CNLLC"
    CNUSA = "CNUSA"

class Currency(str, Enum):
    AED = "AED"
    INR = "INR"
    USD = "USD"

class Incoterm(str, Enum):
    CIF = "CIF"
    CIP = "CIP"
    CPT = "CPT"
    CFR = "CFR"
    DAP = "DAP"
    DDP = "DDP"
    DPU = "DPU"
    EXW = "EXW"
    FAS = "FAS"
    FCA = "FCA"
    FOB = "FOB"

class OpType(str, Enum):
    C = "C"
    U = "U"
    D = "D"

class POType(str, Enum):
    Base = "Base"
    Variation = "Variation"

class ProjectStatus(str, Enum):
    Completed = "Completed"
    Cancelled = "Cancelled"
    In_Progress = "In_Progress"
    On_Hold = "On_Hold"

class ProjectType(str, Enum):
    AMC = "AMC"
    POWER = "POWER"
    SERVICE = "SERVICE"
    SUPPLY = "SUPPLY"
    TURNKEY = "TURNKEY"

class ScopeTypes(str, Enum):
    CNPL = "CNPL"
    CNFZC = "CNFZC"
    CNLLC = "CNLLC"
    CNUSA = "CNUSA"
    Client = "Client"

# Base Models
class RegionBase(SQLModel):
    region_name: str = Field(max_length=255)
    region_code: str = Field(max_length=8)
    description: Optional[str] = Field(sa_column=Column(Text))
    user_tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))

class CountryBase(SQLModel):
    region_id: UUID = Field(foreign_key="regions.id")
    country_name: str = Field(max_length=255)
    country_code: str = Field(max_length=3)
    description: Optional[str] = Field(sa_column=Column(Text))
    user_tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))

class ClientBase(SQLModel):
    region_id: Optional[UUID] = Field(foreign_key="regions.id")
    country_id: Optional[UUID] = Field(foreign_key="countries.id")
    client_id: str = Field(max_length=64)
    client_name: Optional[str] = Field(max_length=255)
    client_address: Optional[dict] = Field(sa_column=Column(JSON))
    client_contact: Optional[dict] = Field(sa_column=Column(JSON))
    description: Optional[str] = Field(sa_column=Column(Text))
    crm_reference: Optional[str] = Field(max_length=255)
    erp_reference: Optional[str] = Field(max_length=255)
    user_tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))

class ProjectBase(SQLModel):
    project_type: ProjectType
    cn_project_code: str = Field(max_length=8)
    project_name: str = Field(max_length=255)
    description: Optional[str] = Field(sa_column=Column(Text))
    client_id: UUID = Field(foreign_key="clients.id")
    end_customer_id: UUID = Field(foreign_key="clients.id")
    tender_reference_code: Optional[str] = Field(max_length=8)
    cn_entity: Optional[CNEntity]
    project_anchor: str = Field(max_length=255)
    project_manager: str = Field(max_length=255)
    start_date: datetime
    delivery_date: datetime
    status: Optional[ProjectStatus]
    user_tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))

class PurchaseOrderBase(SQLModel):
    client_id: UUID = Field(foreign_key="clients.id")
    cn_erp_ref: str = Field(max_length=255)
    client_po_ref: str = Field(max_length=255)
    po_date: datetime
    po_type: POType
    po_incoterms: Optional[Incoterm]
    po_delivery_schedule: Optional[str] = Field(max_length=255)
    po_base_currency: Optional[Currency]
    exchange_rate: Optional[float] = Field(sa_column=Column(Double))
    po_total_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_tax_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_supply_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_inc_rc_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_amc_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_wo_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_to_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_freight_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_ir_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_tr_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_discount_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_taxable_value_inr: Optional[float] = Field(sa_column=Column(Double))
    po_non_taxable_value_inr: Optional[float] = Field(sa_column=Column(Double))
    in_gst_value_inr: Optional[float] = Field(sa_column=Column(Double))
    ae_vat_value_inr: Optional[float] = Field(sa_column=Column(Double))
    us_vat_value_inr: Optional[float] = Field(sa_column=Column(Double))
    abg_terms: Optional[str] = Field(sa_column=Column(Text))
    abg_value_inr: Optional[float] = Field(sa_column=Column(Double))
    pbg_terms: Optional[str] = Field(sa_column=Column(Text))
    pbg_value_inr: Optional[float] = Field(sa_column=Column(Double))
    payment_terms: Optional[str] = Field(sa_column=Column(Text))
    credit_period_days: Optional[int]
    delivery_region: Optional[UUID] = Field(foreign_key="regions.id")
    delivery_country: Optional[UUID] = Field(foreign_key="countries.id")
    delivery_location: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    transport_scope: Optional[ScopeTypes]
    insurance_scope: Optional[ScopeTypes]
    comments: Optional[str] = Field(sa_column=Column(Text))
    user_tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))

# Table Models
class Region(RegionBase, table=True):
    __tablename__ = "regions"
    __table_args__ = (
        UniqueConstraint('region_code', name='regions_region_code_key'),
        Index('idx_regions_region_name', 'region_name'),
        Index('idx_regions_region_code', 'region_code'),
        {'schema': 'public'}
    )
    
    id: UUID = Field(primary_key=True)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )

class Country(CountryBase, table=True):
    __tablename__ = "countries"
    __table_args__ = (
        UniqueConstraint('country_code', name='countries_country_code_key'),
        Index('idx_countries_country_code', 'country_code'),
        Index('idx_countries_country_name', 'country_name'),
        Index('idx_countries_region_id', 'region_id'),
        {'schema': 'public'}
    )
    
    id: UUID = Field(primary_key=True)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )

class Client(ClientBase, table=True):
    __tablename__ = "clients"
    __table_args__ = (
        UniqueConstraint('client_id', name='clients_client_id_key'),
        Index('idx_clients_client_id', 'client_id'),
        Index('idx_clients_country_id', 'country_id'),
        Index('idx_clients_region_id', 'region_id'),
        Index('idx_clients_created_by', 'created_by'),
        Index('idx_clients_updated_by', 'updated_by'),
        {'schema': 'public'}
    )
    
    id: UUID = Field(primary_key=True)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    created_by: str = Field(max_length=255)
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_by: Optional[str] = Field(max_length=255)
    last_op: Optional[OpType]

class Project(ProjectBase, table=True):
    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint('cn_project_code', name='projects_cn_project_code_key'),
        Index('idx_projects_cn_project_code', 'cn_project_code'),
        Index('idx_projects_client_id', 'client_id'),
        Index('idx_projects_end_customer_id', 'end_customer_id'),
        Index('idx_projects_cn_entity', 'cn_entity'),
        Index('idx_projects_project_type', 'project_type'),
        Index('idx_projects_project_anchor', 'project_anchor'),
        Index('idx_projects_project_manager', 'project_manager'),
        Index('idx_projects_created_by', 'created_by'),
        Index('idx_projects_updated_by', 'updated_by'),
        {'schema': 'public'}
    )
    
    id: UUID = Field(primary_key=True)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    created_by: str = Field(max_length=255)
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_by: Optional[str] = Field(max_length=255)
    last_op: Optional[OpType]

class ProjectPO(SQLModel, table=True):
    __tablename__ = "projects_pos"
    __table_args__ = (
        UniqueConstraint('po_id', name='projects_pos_po_id_key'),
        Index('idx_projects_pos_project_id', 'project_id'),
        Index('idx_projects_pos_po_id', 'po_id'),
        Index('idx_projects_pos_created_by', 'created_by'),
        Index('idx_projects_pos_updated_by', 'updated_by'),
        {'schema': 'public'}
    )
    
    id: UUID = Field(primary_key=True)
    project_id: UUID = Field(foreign_key="projects.id")
    po_id: UUID = Field(foreign_key="purchase_orders.id")
    created_by: str = Field(max_length=255)
    updated_by: Optional[str] = Field(max_length=255)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    last_op: Optional[OpType]

class PurchaseOrder(PurchaseOrderBase, table=True):
    __tablename__ = "purchase_orders"
    __table_args__ = (
        Index('idx_purchase_orders_client_id', 'client_id'),
        Index('idx_purchase_orders_cn_erp_ref', 'cn_erp_ref'),
        Index('idx_purchase_orders_client_po_ref', 'client_po_ref'),
        Index('idx_purchase_orders_po_type', 'po_type'),
        Index('idx_purchase_orders_po_base_currency', 'po_base_currency'),
        Index('idx_purchase_orders_delivery_region', 'delivery_region'),
        Index('idx_purchase_orders_delivery_country', 'delivery_country'),
        Index('idx_purchase_orders_created_by', 'created_by'),
        Index('idx_purchase_orders_updated_by', 'updated_by'),
        {'schema': 'public'}
    )
    
    id: UUID = Field(primary_key=True)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    created_by: str = Field(max_length=255)
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_by: Optional[str] = Field(max_length=255)
    last_op: Optional[OpType]

class Employee(SQLModel, table=True):
    __tablename__ = "employee"
    
    emp_id: int = Field(primary_key=True)
    employee_code: Optional[str] = Field(max_length=200)
    employee_name: Optional[str] = Field(max_length=200)
    manager1_code: Optional[str] = Field(max_length=200)
    manager2_code: Optional[str] = Field(max_length=200)
    manager3_code: Optional[str] = Field(max_length=200)
    email: Optional[str] = Field(max_length=100)
    employment_status: Optional[str] = Field(max_length=10)
    exit_date: Optional[str] = Field(max_length=200)
    employment_type: Optional[str] = Field(max_length=50)
    department: Optional[str] = Field(max_length=100)
    user_role: Optional[int]
    location: Optional[str] = Field(max_length=500)
    remarks: Optional[str] = Field(max_length=1000)
    created_by: Optional[str] = Field(max_length=50)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_by: Optional[str] = Field(max_length=200)
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    date_of_resignation: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )

# Additional SQL needed for perfect match:
'''
-- Run these after table creation:
ALTER TABLE IF EXISTS public.regions OWNER to commtel;
ALTER TABLE IF EXISTS public.countries OWNER to commtel;
ALTER TABLE IF EXISTS public.clients OWNER to commtel;
ALTER TABLE IF EXISTS public.projects OWNER to commtel;
ALTER TABLE IF EXISTS public.purchase_orders OWNER to commtel;

-- Set tablespace for each table
ALTER TABLE IF EXISTS public.regions SET TABLESPACE pg_default;
ALTER TABLE IF EXISTS public.countries SET TABLESPACE pg_default;
ALTER TABLE IF EXISTS public.clients SET TABLESPACE pg_default;
ALTER TABLE IF EXISTS public.projects SET TABLESPACE pg_default;
ALTER TABLE IF EXISTS public.purchase_orders SET TABLESPACE pg_default;
'''