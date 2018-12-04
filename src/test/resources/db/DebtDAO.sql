--
-- PostgreSQL database dump
--

-- Dumped from database version 10.5
-- Dumped by pg_dump version 10.5

-- Started on 2018-09-04 17:47:54



--
-- TOC entry 3044 (class 0 OID 21766)
-- Dependencies: 229
-- Data for Name: region; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.region (id, name) VALUES (1, 'Чернівецька область');
INSERT INTO public.region (id, name) VALUES (2, 'Дніпропетровська область');


--
-- TOC entry 3033 (class 0 OID 21711)
-- Dependencies: 218
-- Data for Name: city; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.city (id, name, region_id) VALUES (1, 'Чернівці', 1);
INSERT INTO public.city (id, name, region_id) VALUES (3, 'Кривий Ріг', 2);


--
-- TOC entry 3047 (class 0 OID 21784)
-- Dependencies: 232
-- Data for Name: street; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.street (id, name, city_id) VALUES (1, 'проспект Незалежності', 1);
INSERT INTO public.street (id, name, city_id) VALUES (2, 'вулиця Ватутіна', 1);
INSERT INTO public.street (id, name, city_id) VALUES (3, 'вулиця Винниченка', 1);
INSERT INTO public.street (id, name, city_id) VALUES (4, 'вулиця Поштова', 1);
INSERT INTO public.street (id, name, city_id) VALUES (5, 'вулиця Гагаріна', 1);
INSERT INTO public.street (id, name, city_id) VALUES (6, 'вулиця Толстого', 1);
INSERT INTO public.street (id, name, city_id) VALUES (7, 'вулиця Горького', 1);
INSERT INTO public.street (id, name, city_id) VALUES (8, 'вулиця Сковороди', 1);


--
-- TOC entry 3038 (class 0 OID 21736)
-- Dependencies: 223
-- Data for Name: house; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.house (id, number, street_id) VALUES (1, '131', 1);
INSERT INTO public.house (id, number, street_id) VALUES (2, '18', 2);
INSERT INTO public.house (id, number, street_id) VALUES (3, '3', 3);
INSERT INTO public.house (id, number, street_id) VALUES (4, '1', 4);
INSERT INTO public.house (id, number, street_id) VALUES (5, '4', 5);
INSERT INTO public.house (id, number, street_id) VALUES (6, '2', 6);
INSERT INTO public.house (id, number, street_id) VALUES (7, '12', 7);
INSERT INTO public.house (id, number, street_id) VALUES (8, '43', 8);


--
-- TOC entry 3037 (class 0 OID 21731)
-- Dependencies: 222
-- Data for Name: flat; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.flat (id, number, house_id) VALUES (1, '', 1);
INSERT INTO public.flat (id, number, house_id) VALUES (2, '', 2);
INSERT INTO public.flat (id, number, house_id) VALUES (3, '', 3);
INSERT INTO public.flat (id, number, house_id) VALUES (4, '24', 4);
INSERT INTO public.flat (id, number, house_id) VALUES (5, '123', 5);
INSERT INTO public.flat (id, number, house_id) VALUES (6, '', 6);
INSERT INTO public.flat (id, number, house_id) VALUES (7, '23', 7);
INSERT INTO public.flat (id, number, house_id) VALUES (8, '65', 8);
INSERT INTO public.flat (id, number, house_id) VALUES (9, '5', 7);
INSERT INTO public.flat (id, number, house_id) VALUES (10, '15', 8);


--
-- TOC entry 3032 (class 0 OID 21706)
-- Dependencies: 217
-- Data for Name: addresses; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (1, true, 48.2690871, 25.924404099999947, 1, 1, 1, 1, 1);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (2, true, 48.025148000000002, 33.469425099999967, 1, 2, 2, 1, 2);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (3, true, 48.2708972, 25.953113400000007, 1, 3, 3, 1, 3);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (4, true, 48.293169499999998, 25.934576099999958, 1, 4, 4, 1, 4);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (5, true, 48.297532199999999, 25.936605999999983, 1, 5, 5, 1, 5);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (6, true, 48.295348099999998, 25.934265600000003, 1, 6, 6, 1, 6);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (7, true, 48.295746200000004, 25.93277850000004, 1, 7, 7, 1, 7);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (8, true, 48.292247599999989, 25.928941000000009, 1, 8, 8, 1, 8);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (9, true, 48.292825800000003, 25.934579600000006, 1, 9, 7, 1, 7);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (10, false, 48.2921671, 25.930448399999932, 1, 10, 8, 1, 8);


--
-- TOC entry 3050 (class 0 OID 21799)
-- Dependencies: 235
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (107, NULL, '', 'manager3@gmail.com', NULL, 'Andriy', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'MANAGER', 'Zagarovskiy', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (108, NULL, '', 'manager4@gmail.com', NULL, 'Viktoriya', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'MANAGER', 'Radashko', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (111, NULL, '', 'inspector3@gmail.com', NULL, 'Olga', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'INSPECTOR', 'Ivanova', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (112, NULL, '', 'inspector4@gmail.com', NULL, 'Volodimir', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'INSPECTOR', 'Golovach', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (100, NULL, '', 'admin1@gmail.com', '2018-09-04', 'Ivan', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'ADMIN', 'Petrov', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (101, NULL, '', 'user1@gmail.com', '2018-09-04', 'Mariya', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'USER', 'Chuikina', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (110, NULL, '', 'inspector2@gmail.com', '2018-09-04', 'Makar', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'INSPECTOR', 'Portnov', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (105, NULL, '', 'manager1@gmail.com', '2018-09-04', 'Viktor', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'MANAGER', 'Volchinskiy', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (106, NULL, '', 'manager2@gmail.com', '2018-09-04', 'Ilya', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'MANAGER', 'Sherbunchak', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (102, NULL, '', 'user2@gmail.com', '2018-09-04', 'Valera', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780812', 'USER', 'Dobkin', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (103, NULL, '', 'user3@gmail.com', '2018-09-04', 'Pavel', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780812', 'USER', 'Chernov', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (104, NULL, '', 'user4@gmail.com', '2018-09-04', 'Germiona', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780812', 'USER', 'Potter', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (109, NULL, '', 'inspector1@gmail.com', '2018-09-04', 'Oleg', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'INSPECTOR', 'Adamov', 'ACTIVE');


--
-- TOC entry 3051 (class 0 OID 21807)
-- Dependencies: 236
-- Data for Name: utilities; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.utilities (id, is_active, identification_code, logo, name, address_id, user_id) VALUES (3, true, '01124343255673', NULL, 'unfixed counters"', 3, 106);
INSERT INTO public.utilities (id, is_active, identification_code, logo, name, address_id, user_id) VALUES (2, true, '12345678', NULL, 'fixed counters',  1, 105);


--
-- TOC entry 3035 (class 0 OID 21721)
-- Dependencies: 220
-- Data for Name: debts; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (1, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (2, NULL, NULL, NULL, -50, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (3, NULL, NULL, NULL, 3, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (4, NULL, NULL, NULL, 4, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (5, NULL, NULL, NULL, 5, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (6, NULL, NULL, NULL, 6, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (7, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (8, NULL, NULL, NULL, 8, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (9, NULL, NULL, NULL, 9, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (10, NULL, NULL, '2018-08-3', 10, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (11, NULL, '2018-08-25', NULL, 11, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (12, '2018-09-01', NULL, NULL, 13, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (13, NULL, NULL, NULL, 13, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (14, NULL, NULL, NULL, 14, 3);
--
-- TOC entry 3034 (class 0 OID 21716)
-- Dependencies: 219
-- Data for Name: counters; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (1, true, 1, true, NULL, 1, 4, 1, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (2, true, 1, false, NULL, 1, 4, 2, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (3, true, 1, true, '2018-08-25', 1, 5, 3, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (4, true, 1, false, NULL, 1, 5, 4, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (5, true, 1, true, NULL, 1, 6, 5, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (6, true, 1, false, NULL, 1, 6, 6, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (7, false, 0, true, NULL, 1, 7, 7, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (8, false, 1, false, NULL, 1, 7, 8, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (9, true, 1, true, NULL, 1, 8, 9, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (10, true, 1, false, '2018-08-25', 1, 8, 10, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (11, true, 1, true, NULL, 1, 9, 11, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (12, true, 1, false, NULL, 1, 9, 12, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (13, true, 1, true, NULL, 1, 10, 13, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (14, true, 1, false, NULL, 1, 10, 14, 104);



--
-- TOC entry 3013 (class 0 OID 21664)
-- Dependencies: 198
-- Data for Name: databasechangelog; Type: TABLE DATA; Schema: public; Owner: postgres
--

--
-- TOC entry 3012 (class 0 OID 21659)
-- Dependencies: 197
-- Data for Name: databasechangeloglock; Type: TABLE DATA; Schema: public; Owner: postgres
--


--
-- TOC entry 3036 (class 0 OID 21726)
-- Dependencies: 221
-- Data for Name: email_token; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- TOC entry 3041 (class 0 OID 21751)
-- Dependencies: 226
-- Data for Name: prices; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.prices (price_id, active, date, price, utility_id) VALUES (2, true, '2018-09-04', 3.3300000000000001, 2);
INSERT INTO public.prices (price_id, active, date, price, utility_id) VALUES (3, true, '2018-09-04', 5.3600000000000003, 3);


--
-- TOC entry 3039 (class 0 OID 21741)
-- Dependencies: 224
-- Data for Name: new_prices; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.new_prices (new_price_id, activation_date, new_price, current_price_id) VALUES (1, '2018-10-01', 36.149999999999999, 2);
INSERT INTO public.new_prices (new_price_id, activation_date, new_price, current_price_id) VALUES (2, '2018-09-30', 7.25, 3);


--
-- TOC entry 3040 (class 0 OID 21746)
-- Dependencies: 225
-- Data for Name: payments_histories; Type: TABLE DATA; Schema: public; Owner: postgres
--


--
-- TOC entry 3042 (class 0 OID 21756)
-- Dependencies: 227
-- Data for Name: rating; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.rating (id, rating, user_id) VALUES (2, 3.5, 101);
INSERT INTO public.rating (id, rating, user_id) VALUES (1, 4, 109);


--
-- TOC entry 3043 (class 0 OID 21761)
-- Dependencies: 228
-- Data for Name: rating_list_item; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.rating_list_item (id, rating_value, user_id, rater_user_id) VALUES (2, 3.5, 101, 109);
INSERT INTO public.rating_list_item (id, rating_value, user_id, rater_user_id) VALUES (1, 4, 109, 101);


--
-- TOC entry 3045 (class 0 OID 21771)
-- Dependencies: 230
-- Data for Name: schedule_history; Type: TABLE DATA; Schema: public; Owner: postgres
--





--
-- TOC entry 3049 (class 0 OID 21794)
-- Dependencies: 234
-- Data for Name: user_address; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.user_address (user_id, address_id) VALUES (101, 4);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 5);

INSERT INTO public.user_address (user_id, address_id) VALUES (102, 6);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 7);

INSERT INTO public.user_address (user_id, address_id) VALUES (103, 8);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 9);

INSERT INTO public.user_address (user_id, address_id) VALUES (104, 10);


--
-- TOC entry 3052 (class 0 OID 21815)
-- Dependencies: 237
-- Data for Name: utilities_counters; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 1);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 2);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 3);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 4);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 5);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 6);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 7);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 8);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 9);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 10);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 11);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 12);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 13);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 14);


--
-- TOC entry 3053 (class 0 OID 21820)
-- Dependencies: 238
-- Data for Name: utilities_users; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.utilities_users (utility_id, user_id) VALUES (2, 109);
INSERT INTO public.utilities_users (utility_id, user_id) VALUES (2, 110);
INSERT INTO public.utilities_users (utility_id, user_id) VALUES (3, 111);
INSERT INTO public.utilities_users (utility_id, user_id) VALUES (3, 112);

