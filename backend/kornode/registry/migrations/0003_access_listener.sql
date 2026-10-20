-- P4-04 (D-67): settings of an agent's access listener (hostname, port, udp)
-- and its hub-issued server certificate; the key is encrypted with the hub
-- master key. JSON object, empty when the listener is not configured.
ALTER TABLE nodes ADD COLUMN access TEXT NOT NULL DEFAULT '{}';
