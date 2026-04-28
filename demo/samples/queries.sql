-- Fictional SQL demo data. Domains use example.invalid and IPs use TEST-NET ranges.
SELECT p.passenger_id, p.email, p.phone, b.card_last4
FROM passengers p
JOIN bookings b ON b.passenger_id = p.passenger_id
WHERE p.email = 'casey.traveler@example.invalid'
  AND p.phone = '+1 202-555-0199'
  AND b.client_ip = '192.0.2.42';

INSERT INTO support_events (ticket_id, reporter_email, source_ip, note)
VALUES ('ST-1007', 'avery.reporter@example.invalid', '198.51.100.24', 'Fictional card 4111 1111 1111 1111 was declined');
