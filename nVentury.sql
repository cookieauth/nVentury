-- Drop and recreate the database (Be careful in production environments)
DROP DATABASE IF EXISTS inventory;
CREATE DATABASE inventory;
\c inventory;

-- Master inventory table
CREATE TABLE inventory (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    serial_number VARCHAR(100) UNIQUE,
    host_name VARCHAR(255),
    mac VARCHAR(50),
    ip_address VARCHAR(50),
    make VARCHAR(100),
    model VARCHAR(100),
    department VARCHAR(100),
    status VARCHAR(50),
    notes TEXT,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    location VARCHAR(255)
);

-- Trigger function to update updated_at on inventory
CREATE OR REPLACE FUNCTION set_inventory_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_inventory_set_updated_at
BEFORE UPDATE ON inventory
FOR EACH ROW
EXECUTE FUNCTION set_inventory_updated_at();

-- Data sources meta table
CREATE TABLE data_sources (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    last_update TIMESTAMP
);

INSERT INTO data_sources (name, description) VALUES
('Forescout', 'Data collected from Forescout platform'),
('ActiveDirectory', 'Data collected from Active Directory'),
('SecurityCenter', 'Data collected from Security Center'),
('HBSS', 'Data collected from Host-Based Security System');

-- Source-specific tables
CREATE TABLE forescout_data (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    inventory_id INT,
    collected_ip VARCHAR(50),
    collected_mac VARCHAR(50),
    collected_host_name VARCHAR(255),
    last_seen TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inventory_id) REFERENCES inventory(id) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE ad_data (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    inventory_id INT,
    collected_host_name VARCHAR(255),
    collected_ip VARCHAR(50),
    department VARCHAR(100),
    last_seen TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inventory_id) REFERENCES inventory(id) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE securitycenter_data (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    inventory_id INT,
    collected_ip VARCHAR(50),
    collected_mac VARCHAR(50),
    vulnerabilities_count INT,
    last_seen TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inventory_id) REFERENCES inventory(id) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE hbss_data (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    inventory_id INT,
    collected_mac VARCHAR(50),
    collected_host_name VARCHAR(255),
    status VARCHAR(50),
    last_seen TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inventory_id) REFERENCES inventory(id) ON DELETE SET NULL ON UPDATE CASCADE
);

-- Indices
CREATE INDEX idx_inventory_mac ON inventory(mac);
CREATE INDEX idx_inventory_host_name ON inventory(host_name);
CREATE INDEX idx_inventory_serial_number ON inventory(serial_number);

CREATE INDEX idx_forescout_data_mac ON forescout_data(collected_mac);
CREATE INDEX idx_ad_data_host_name ON ad_data(collected_host_name);
CREATE INDEX idx_securitycenter_data_ip ON securitycenter_data(collected_ip);
CREATE INDEX idx_hbss_data_mac ON hbss_data(collected_mac);

-- Trigger functions for each source: before insert (to find/create inventory), after insert (to update inventory)

-- Forescout triggers
CREATE OR REPLACE FUNCTION trg_forescout_data_before_insert_fnc()
RETURNS TRIGGER AS $$
DECLARE
    inv_id INT;
BEGIN
    IF NEW.inventory_id IS NULL THEN
        -- Match by MAC
        SELECT id INTO inv_id FROM inventory WHERE mac = NEW.collected_mac LIMIT 1;
        IF NOT FOUND THEN
            -- If no MAC match, try host_name
            SELECT id INTO inv_id FROM inventory WHERE host_name = NEW.collected_host_name LIMIT 1;
        END IF;

        IF FOUND THEN
            NEW.inventory_id = inv_id;
        ELSE
            -- Insert a new inventory entry
            INSERT INTO inventory (serial_number, host_name, mac, ip_address, last_seen, location)
            VALUES (NULL, NEW.collected_host_name, NEW.collected_mac, NEW.collected_ip, NEW.last_seen, NULL)
            RETURNING id INTO inv_id;
            NEW.inventory_id = inv_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_forescout_data_before_insert
BEFORE INSERT ON forescout_data
FOR EACH ROW
EXECUTE FUNCTION trg_forescout_data_before_insert_fnc();

CREATE OR REPLACE FUNCTION trg_forescout_data_after_insert_fnc()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE inventory
       SET ip_address = COALESCE(NEW.collected_ip, ip_address),
           mac = COALESCE(NEW.collected_mac, mac),
           host_name = COALESCE(NEW.collected_host_name, host_name),
           last_seen = GREATEST(COALESCE(last_seen, '1970-01-01'::timestamp), NEW.last_seen)
     WHERE id = NEW.inventory_id;

    UPDATE data_sources SET last_update = CURRENT_TIMESTAMP WHERE name = 'Forescout';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_forescout_data_after_insert
AFTER INSERT ON forescout_data
FOR EACH ROW
EXECUTE FUNCTION trg_forescout_data_after_insert_fnc();

-- Active Directory triggers
CREATE OR REPLACE FUNCTION trg_ad_data_before_insert_fnc()
RETURNS TRIGGER AS $$
DECLARE
    inv_id INT;
BEGIN
    IF NEW.inventory_id IS NULL THEN
        -- Try matching by host_name
        SELECT id INTO inv_id FROM inventory WHERE host_name = NEW.collected_host_name LIMIT 1;
        IF NOT FOUND THEN
            -- If no match by host_name, try ip
            SELECT id INTO inv_id FROM inventory WHERE ip_address = NEW.collected_ip LIMIT 1;
        END IF;

        IF FOUND THEN
            NEW.inventory_id = inv_id;
        ELSE
            INSERT INTO inventory (serial_number, host_name, mac, ip_address, last_seen, department)
            VALUES (NULL, NEW.collected_host_name, NULL, NEW.collected_ip, NEW.last_seen, NEW.department)
            RETURNING id INTO inv_id;
            NEW.inventory_id = inv_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ad_data_before_insert
BEFORE INSERT ON ad_data
FOR EACH ROW
EXECUTE FUNCTION trg_ad_data_before_insert_fnc();

CREATE OR REPLACE FUNCTION trg_ad_data_after_insert_fnc()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE inventory
       SET host_name = COALESCE(NEW.collected_host_name, host_name),
           ip_address = COALESCE(NEW.collected_ip, ip_address),
           department = COALESCE(NEW.department, department),
           last_seen = GREATEST(COALESCE(last_seen, '1970-01-01'::timestamp), NEW.last_seen)
     WHERE id = NEW.inventory_id;

    UPDATE data_sources SET last_update = CURRENT_TIMESTAMP WHERE name = 'ActiveDirectory';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ad_data_after_insert
AFTER INSERT ON ad_data
FOR EACH ROW
EXECUTE FUNCTION trg_ad_data_after_insert_fnc();

-- SecurityCenter triggers
CREATE OR REPLACE FUNCTION trg_securitycenter_data_before_insert_fnc()
RETURNS TRIGGER AS $$
DECLARE
    inv_id INT;
BEGIN
    IF NEW.inventory_id IS NULL THEN
        -- Try matching by MAC
        SELECT id INTO inv_id FROM inventory WHERE mac = NEW.collected_mac LIMIT 1;
        IF NOT FOUND THEN
            -- If no MAC match, try ip
            SELECT id INTO inv_id FROM inventory WHERE ip_address = NEW.collected_ip LIMIT 1;
        END IF;

        IF FOUND THEN
            NEW.inventory_id = inv_id;
        ELSE
            -- Insert a new inventory entry
            INSERT INTO inventory (serial_number, host_name, mac, ip_address, last_seen)
            VALUES (NULL, NULL, NEW.collected_mac, NEW.collected_ip, NEW.last_seen)
            RETURNING id INTO inv_id;
            NEW.inventory_id = inv_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_securitycenter_data_before_insert
BEFORE INSERT ON securitycenter_data
FOR EACH ROW
EXECUTE FUNCTION trg_securitycenter_data_before_insert_fnc();

CREATE OR REPLACE FUNCTION trg_securitycenter_data_after_insert_fnc()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE inventory
       SET ip_address = COALESCE(NEW.collected_ip, ip_address),
           mac = COALESCE(NEW.collected_mac, mac),
           last_seen = GREATEST(COALESCE(last_seen, '1970-01-01'::timestamp), NEW.last_seen)
     WHERE id = NEW.inventory_id;

    UPDATE data_sources SET last_update = CURRENT_TIMESTAMP WHERE name = 'SecurityCenter';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_securitycenter_data_after_insert
AFTER INSERT ON securitycenter_data
FOR EACH ROW
EXECUTE FUNCTION trg_securitycenter_data_after_insert_fnc();

-- HBSS triggers
CREATE OR REPLACE FUNCTION trg_hbss_data_before_insert_fnc()
RETURNS TRIGGER AS $$
DECLARE
    inv_id INT;
BEGIN
    IF NEW.inventory_id IS NULL THEN
        -- Try matching by MAC
        SELECT id INTO inv_id FROM inventory WHERE mac = NEW.collected_mac LIMIT 1;
        IF NOT FOUND THEN
            -- If no MAC match, try host_name
            SELECT id INTO inv_id FROM inventory WHERE host_name = NEW.collected_host_name LIMIT 1;
        END IF;

        IF FOUND THEN
            NEW.inventory_id = inv_id;
        ELSE
            INSERT INTO inventory (serial_number, host_name, mac, last_seen)
            VALUES (NULL, NEW.collected_host_name, NEW.collected_mac, NEW.last_seen)
            RETURNING id INTO inv_id;
            NEW.inventory_id = inv_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_hbss_data_before_insert
BEFORE INSERT ON hbss_data
FOR EACH ROW
EXECUTE FUNCTION trg_hbss_data_before_insert_fnc();

CREATE OR REPLACE FUNCTION trg_hbss_data_after_insert_fnc()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE inventory
       SET mac = COALESCE(NEW.collected_mac, mac),
           host_name = COALESCE(NEW.collected_host_name, host_name),
           last_seen = GREATEST(COALESCE(last_seen, '1970-01-01'::timestamp), NEW.last_seen)
     WHERE id = NEW.inventory_id;

    UPDATE data_sources SET last_update = CURRENT_TIMESTAMP WHERE name = 'HBSS';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_hbss_data_after_insert
AFTER INSERT ON hbss_data
FOR EACH ROW
EXECUTE FUNCTION trg_hbss_data_after_insert_fnc();

-- Views for comparisons
CREATE OR REPLACE VIEW v_inventory_vs_forescout AS
SELECT i.id AS inventory_id,
       i.serial_number,
       i.host_name AS inventory_host,
       f.collected_host_name AS forescout_host,
       i.mac AS inventory_mac,
       f.collected_mac AS forescout_mac,
       i.ip_address AS inventory_ip,
       f.collected_ip AS forescout_ip,
       i.last_seen AS inventory_last_seen,
       f.last_seen AS forescout_last_seen
FROM inventory i
LEFT JOIN forescout_data f ON i.id = f.inventory_id;

CREATE OR REPLACE VIEW v_inventory_vs_ad AS
SELECT i.id AS inventory_id,
       i.serial_number,
       i.host_name AS inventory_host,
       ad.collected_host_name AS ad_host,
       i.ip_address AS inventory_ip,
       ad.collected_ip AS ad_ip,
       i.department AS inventory_dept,
       ad.department AS ad_dept,
       i.last_seen AS inventory_last_seen,
       ad.last_seen AS ad_last_seen
FROM inventory i
LEFT JOIN ad_data ad ON i.id = ad.inventory_id;

CREATE OR REPLACE VIEW v_inventory_vs_securitycenter AS
SELECT i.id AS inventory_id,
       i.serial_number,
       i.host_name AS inventory_host,
       i.mac AS inventory_mac,
       sc.collected_mac AS sc_mac,
       i.ip_address AS inventory_ip,
       sc.collected_ip AS sc_ip,
       i.last_seen AS inventory_last_seen,
       sc.last_seen AS sc_last_seen,
       sc.vulnerabilities_count
FROM inventory i
LEFT JOIN securitycenter_data sc ON i.id = sc.inventory_id;

CREATE OR REPLACE VIEW v_inventory_vs_hbss AS
SELECT i.id AS inventory_id,
       i.serial_number,
       i.host_name AS inventory_host,
       hbss.collected_host_name AS hbss_host,
       i.mac AS inventory_mac,
       hbss.collected_mac AS hbss_mac,
       i.last_seen AS inventory_last_seen,
       hbss.last_seen AS hbss_last_seen,
       hbss.status AS hbss_status
FROM inventory i
LEFT JOIN hbss_data hbss ON i.id = hbss.inventory_id;
