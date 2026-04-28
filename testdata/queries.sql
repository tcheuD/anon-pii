SELECT c.contact_code, c.name, c.email, t.trip_number, t.vehicle_reg
FROM support_contacts c
JOIN trip_assignments ta ON c.id = ta.contact_id
JOIN trips t ON ta.trip_id = t.id
WHERE c.email = 'avery.support@example.invalid'
  AND t.vehicle_reg = 'N123AB'
  AND c.phone = '+1 202-555-0142';

INSERT INTO incident_reports (trip, vehicle, contact_code, description, reporter_email)
VALUES ('AF4412', 'N123AB', 'AVX', 'Fictional passenger complaint from casey.traveler@example.invalid, IP 192.0.2.100', 'ops@example.invalid');

UPDATE support_contacts SET iban = 'FR7630006000011234567890189', phone = '+1 202-555-0178'
WHERE email = 'morgan.support@example.invalid';

DELETE FROM sessions WHERE user_ip = '198.51.100.201' AND user_email = 'riley.agent@example.invalid';
