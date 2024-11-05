from datetime import datetime
from typing import Optional, List
from uuid import UUID
from sqlmodel import SQLModel, Field
from sqlalchemy import Column, DateTime, UniqueConstraint, Index, Text, ARRAY, JSON
from pydantic import Json

# Enums
from enum import Enum

class OpType(str, Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"

class ProjectType(str, Enum):
    STANDARD = "STANDARD"
    CUSTOM = "CUSTOM"

class ProjectStatus(str, Enum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    ON_HOLD = "ON_HOLD"

class CNEntity(str, Enum):
    ENTITY_A = "ENTITY_A"
    ENTITY_B = "ENTITY_B"

class POType(str, Enum):
    SUPPLY = "SUPPLY"
    SERVICE = "SERVICE"

class Incoterm(str, Enum):
    FOB = "FOB"
    CIF = "CIF"
    EXW = "EXW"

class Currency(str, Enum):
    USD = "USD"
    EUR = "EUR"
    INR = "INR"

class ScopeTypes(str, Enum):
    BUYER = "BUYER"
    SELLER = "SELLER"

# Base Models
class RegionBase(SQLModel):
    region_name: str = Field(max_length=255)
    region_code: str = Field(max_length=8)
    description: Optional[str] = Field(sa_column=Column(Text))
    user_tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))

class Region(RegionBase, table=True):
    __tablename__ = "regions"
    __table_args__ = (
        UniqueConstraint('region_code', name='regions_region_code_key'),
        Index('idx_regions_region_name', 'region_name'),
        {'schema': 'public'}
    )
    
    id: UUID = Field(primary_key=True)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )

class CountryBase(SQLModel):
    region_id: Optional[UUID] = Field(foreign_key="regions.id")
    country_name: str = Field(max_length=255)
    country_code: str = Field(max_length=3)
    description: Optional[str] = Field(sa_column=Column(Text))
    user_tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))

class Country(CountryBase, table=True):
    __tablename__ = "countries"
    __table_args__ = (
        UniqueConstraint('country_code', name='countries_country_code_key'),
        {'schema': 'public'}
    )
    
    id: UUID = Field(primary_key=True)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )

class ClientBase(SQLModel):
    region_id: Optional[UUID] = Field(foreign_key="regions.id")
    country_id: Optional[UUID] = Field(foreign_key="countries.id")
    client_id: str = Field(max_length=64)
    client_name: str = Field(max_length=255)
    client_address: Optional[dict] = Field(sa_column=Column(JSON))
    client_contact: Optional[dict] = Field(sa_column=Column(JSON))
    description: Optional[str] = Field(sa_column=Column(Text))
    crm_reference: Optional[str] = Field(max_length=255)
    erp_reference: Optional[str] = Field(max_length=255)
    user_tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    client_type: Optional[str] = Field(max_length=20)
    last_op: Optional[OpType] = None

class Client(ClientBase, table=True):
    __tablename__ = "clients"
    __table_args__ = (
        UniqueConstraint('client_id', name='clients_client_id_key'),
        UniqueConstraint('created_by', name='clients_created_by_key'),
        {'schema': 'public'}
    )
    
    id: UUID = Field(primary_key=True)
    created_by: str = Field(max_length=255)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_by: Optional[str] = Field(max_length=255)
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )

class ProjectBase(SQLModel):
    project_type: ProjectType
    cn_project_code: str = Field(max_length=8)
    project_name: str = Field(max_length=255)
    description: Optional[str] = Field(sa_column=Column(Text))
    client_id: UUID = Field(foreign_key="clients.id")
    end_customer_id: UUID = Field(foreign_key="clients.id")
    tender_reference_code: Optional[str] = Field(max_length=8)
    cn_entity: Optional[CNEntity] = None
    project_anchor: str = Field(max_length=255)
    project_manager: str = Field(max_length=255)
    start_date: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    delivery_date: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    status: Optional[ProjectStatus] = None
    user_tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    last_op: Optional[OpType] = None

class Project(ProjectBase, table=True):
    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint('cn_project_code', name='projects_cn_project_code_key'),
        {'schema': 'public'}
    )
    
    id: UUID = Field(primary_key=True)
    created_by: str = Field(max_length=255)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_by: Optional[str] = Field(max_length=255)
    updated_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )

class PurchaseOrderBase(SQLModel):
    client_id: UUID = Field(foreign_key="clients.id")
    cn_erp_ref: str = Field(max_length=255)
    client_po_ref: str = Field(max_length=255)
    po_date: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    po_type: POType
    po_incoterms: Optional[Incoterm] = None
    po_delivery_schedule: Optional[str] = Field(max_length=255)
    po_base_currency: Optional[Currency] = None
    exchange_rate: Optional[float] = Field(default=None)
    po_total_value_inr: Optional[float] = Field(default=None)
    po_tax_value_inr: Optional[float] = Field(default=None)
    po_supply_value_inr: Optional[float] = Field(default=None)
    po_inc_rc_value_inr: Optional[float] = Field(default=None)
    po_amc_value_inr: Optional[float] = Field(default=None)
    po_wo_value_inr: Optional[float] = Field(default=None)
    po_to_value_inr: Optional[float] = Field(default=None)
    po_freight_value_inr: Optional[float] = Field(default=None)
    po_ir_value_inr: Optional[float] = Field(default=None)
    po_tr_value_inr: Optional[float] = Field(default=None)
    po_discount_value_inr: Optional[float] = Field(default=None)
    po_taxable_value_inr: Optional[float] = Field(default=None)
    po_non_taxable_value_inr: Optional[float] = Field(default=None)
    in_gst_value_inr: Optional[float] = Field(default=None)
    ae_vat_value_inr: Optional[float] = Field(default=None)
    us_vat_value_inr: Optional[float] = Field(default=None)
    abg_terms: Optional[str] = Field(sa_column=Column(Text))
    abg_value_inr: Optional[float] = Field(default=None)
    pbg_terms: Optional[str] = Field(sa_column=Column(Text))
    pbg_value_inr: Optional[float] = Field(default=None)
    payment_terms: Optional[str] = Field(sa_column=Column(Text))
    credit_period_days: Optional[float] = Field(default=None)
    delivery_region: Optional[UUID] = Field(foreign_key="regions.id")
    delivery_country: Optional[UUID] = Field(foreign_key="countries.id")
    delivery_location: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    transport_scope: Optional[ScopeTypes] = None
    insurance_scope: Optional[ScopeTypes] = None
    comments: Optional[str] = Field(sa_column=Column(Text))
    user_tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    last_op: Optional[OpType] = None

class PurchaseOrder(PurchaseOrderBase, table=True):
    __tablename__ = "purchase_orders"
    __table_args__ = {'schema': 'public'}
    
    id: UUID = Field(primary_key=True)
    created_by: str = Field(max_length=255)
    created_at: Optional[datetime] = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    updated_by: Optional[str] = Field(max_length=255)
    updated_at: Optional[datetime] = Field(
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