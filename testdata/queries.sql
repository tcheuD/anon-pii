SELECT c.crew_code, c.name, c.email, f.flight_number, f.aircraft_reg
FROM crew c
JOIN flight_assignments fa ON c.id = fa.crew_id
JOIN flights f ON fa.flight_id = f.id
WHERE c.email = 'jean.dupont@example-air.com'
  AND f.aircraft_reg = 'F-HOPA'
  AND c.phone = '+33 6 12 34 56 78';

INSERT INTO incident_reports (flight, aircraft, crew_code, description, reporter_email)
VALUES ('IZM4412', 'F-HOPA', 'JDU', 'Pilot arrived late, passenger complaint from sophie.lambert@gmail.com, IP 192.168.1.100', 'ops@example-air.com');

UPDATE crew SET iban = 'FR7630006000011234567890189', phone = '06 98 76 54 32'
WHERE email = 'marie.martin@example-air.com';

DELETE FROM sessions WHERE user_ip = '10.42.8.201' AND user_email = 'pierre.bernard@example-air.com';
