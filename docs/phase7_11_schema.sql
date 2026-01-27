-- ============================================================================
-- Phase 7-11 Extension Database Schema
-- For: secDNS (DNSSEC), IDN, Variant, KV extensions
-- ============================================================================

-- ============================================================================
-- Phase 7: DNSSEC (secDNS) Tables
-- ============================================================================

-- DNSSEC Configuration (max signature lifetime per domain)
CREATE TABLE DOMAIN_DNSSEC_CONFIG (
    CONFIG_ID       NUMBER PRIMARY KEY,
    DOM_ROID        VARCHAR2(50) NOT NULL,
    MAX_SIG_LIFE    NUMBER,
    CREATE_DATE     DATE DEFAULT SYSDATE,
    UPDATE_DATE     DATE,
    CONSTRAINT FK_DNSSEC_CFG_DOM FOREIGN KEY (DOM_ROID) REFERENCES DOMAINS(ROID)
);

CREATE UNIQUE INDEX UK_DNSSEC_CFG_DOM ON DOMAIN_DNSSEC_CONFIG(DOM_ROID);
CREATE SEQUENCE DNSSEC_CONFIG_SEQ START WITH 1 INCREMENT BY 1;

-- DNSSEC DS (Delegation Signer) Records
CREATE TABLE DOMAIN_DNSSEC_DS (
    DS_ID           NUMBER PRIMARY KEY,
    DOM_ROID        VARCHAR2(50) NOT NULL,
    KEY_TAG         NUMBER(5) NOT NULL,      -- 0-65535
    ALG             NUMBER(3) NOT NULL,       -- Algorithm number
    DIGEST_TYPE     NUMBER(3) NOT NULL,       -- 1=SHA-1, 2=SHA-256, 4=SHA-384
    DIGEST          VARCHAR2(1024) NOT NULL,  -- Hex-encoded digest
    -- Optional embedded key data
    KEY_FLAGS       NUMBER(5),                -- 256=ZSK, 257=KSK
    KEY_PROTOCOL    NUMBER(3),                -- Always 3 for DNSSEC
    KEY_ALG         NUMBER(3),                -- Algorithm number
    PUB_KEY         CLOB,                     -- Base64-encoded public key
    CREATE_DATE     DATE DEFAULT SYSDATE,
    CONSTRAINT FK_DNSSEC_DS_DOM FOREIGN KEY (DOM_ROID) REFERENCES DOMAINS(ROID)
);

CREATE INDEX IX_DNSSEC_DS_DOM ON DOMAIN_DNSSEC_DS(DOM_ROID);
CREATE SEQUENCE DNSSEC_DS_SEQ START WITH 1 INCREMENT BY 1;

-- DNSSEC Key Records (standalone, not embedded in DS)
CREATE TABLE DOMAIN_DNSSEC_KEY (
    KEY_ID          NUMBER PRIMARY KEY,
    DOM_ROID        VARCHAR2(50) NOT NULL,
    FLAGS           NUMBER(5) NOT NULL,       -- 256=ZSK, 257=KSK
    PROTOCOL        NUMBER(3) NOT NULL,       -- Always 3 for DNSSEC
    ALG             NUMBER(3) NOT NULL,       -- Algorithm number
    PUB_KEY         CLOB NOT NULL,            -- Base64-encoded public key
    CREATE_DATE     DATE DEFAULT SYSDATE,
    CONSTRAINT FK_DNSSEC_KEY_DOM FOREIGN KEY (DOM_ROID) REFERENCES DOMAINS(ROID)
);

CREATE INDEX IX_DNSSEC_KEY_DOM ON DOMAIN_DNSSEC_KEY(DOM_ROID);
CREATE SEQUENCE DNSSEC_KEY_SEQ START WITH 1 INCREMENT BY 1;

-- ============================================================================
-- Phase 8: IDN (Internationalized Domain Names) Table
-- ============================================================================

CREATE TABLE DOMAIN_IDN (
    IDN_ID          NUMBER PRIMARY KEY,
    DOM_ROID        VARCHAR2(50) NOT NULL,
    USER_FORM       NVARCHAR2(255) NOT NULL,  -- Unicode form (e.g., "mxn--chen.ae")
    LANGUAGE        VARCHAR2(10) NOT NULL,     -- BCP 47 language tag (e.g., "ar", "de")
    CANONICAL_FORM  VARCHAR2(255),             -- Server-computed canonical form
    CREATE_DATE     DATE DEFAULT SYSDATE,
    UPDATE_DATE     DATE,
    CONSTRAINT FK_IDN_DOM FOREIGN KEY (DOM_ROID) REFERENCES DOMAINS(ROID)
);

CREATE UNIQUE INDEX UK_IDN_DOM ON DOMAIN_IDN(DOM_ROID);
CREATE SEQUENCE DOMAIN_IDN_SEQ START WITH 1 INCREMENT BY 1;

-- ============================================================================
-- Phase 9: Variant Extension Table
-- ============================================================================

CREATE TABLE DOMAIN_VARIANTS (
    VARIANT_ID      NUMBER PRIMARY KEY,
    DOM_ROID        VARCHAR2(50) NOT NULL,
    VARIANT_NAME    VARCHAR2(255) NOT NULL,   -- DNS form of variant
    USER_FORM       NVARCHAR2(255) NOT NULL,  -- Unicode user form
    CREATE_DATE     DATE DEFAULT SYSDATE,
    CONSTRAINT FK_VARIANT_DOM FOREIGN KEY (DOM_ROID) REFERENCES DOMAINS(ROID)
);

CREATE INDEX IX_VARIANT_DOM ON DOMAIN_VARIANTS(DOM_ROID);
CREATE UNIQUE INDEX UK_VARIANT_NAME ON DOMAIN_VARIANTS(DOM_ROID, VARIANT_NAME);
CREATE SEQUENCE DOMAIN_VARIANT_SEQ START WITH 1 INCREMENT BY 1;

-- ============================================================================
-- Phase 11: KV (Key-Value) Extension Table
-- ============================================================================

CREATE TABLE DOMAIN_KV (
    KV_ID           NUMBER PRIMARY KEY,
    DOM_ROID        VARCHAR2(50) NOT NULL,
    LIST_NAME       VARCHAR2(100) NOT NULL,   -- e.g., "metadata"
    KEY_NAME        VARCHAR2(100) NOT NULL,   -- e.g., "category"
    VALUE           VARCHAR2(4000),           -- e.g., "premium"
    CREATE_DATE     DATE DEFAULT SYSDATE,
    CONSTRAINT FK_KV_DOM FOREIGN KEY (DOM_ROID) REFERENCES DOMAINS(ROID)
);

CREATE INDEX IX_KV_DOM ON DOMAIN_KV(DOM_ROID);
CREATE UNIQUE INDEX UK_KV_KEY ON DOMAIN_KV(DOM_ROID, LIST_NAME, KEY_NAME);
CREATE SEQUENCE DOMAIN_KV_SEQ START WITH 1 INCREMENT BY 1;

-- ============================================================================
-- Cleanup on domain deletion (add triggers or use application logic)
-- ============================================================================

-- Optional: Create a trigger to clean up extension data when domain is deleted
-- This depends on your deletion strategy (soft delete vs hard delete)

/*
CREATE OR REPLACE TRIGGER TRG_DOMAIN_DELETE_EXTENSIONS
BEFORE DELETE ON DOMAINS
FOR EACH ROW
BEGIN
    DELETE FROM DOMAIN_DNSSEC_CONFIG WHERE DOM_ROID = :OLD.ROID;
    DELETE FROM DOMAIN_DNSSEC_DS WHERE DOM_ROID = :OLD.ROID;
    DELETE FROM DOMAIN_DNSSEC_KEY WHERE DOM_ROID = :OLD.ROID;
    DELETE FROM DOMAIN_IDN WHERE DOM_ROID = :OLD.ROID;
    DELETE FROM DOMAIN_VARIANTS WHERE DOM_ROID = :OLD.ROID;
    DELETE FROM DOMAIN_KV WHERE DOM_ROID = :OLD.ROID;
END;
/
*/

-- ============================================================================
-- Grants (adjust schema owner as needed)
-- ============================================================================

-- GRANT SELECT, INSERT, UPDATE, DELETE ON DOMAIN_DNSSEC_CONFIG TO EPP_APP;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON DOMAIN_DNSSEC_DS TO EPP_APP;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON DOMAIN_DNSSEC_KEY TO EPP_APP;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON DOMAIN_IDN TO EPP_APP;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON DOMAIN_VARIANTS TO EPP_APP;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON DOMAIN_KV TO EPP_APP;
